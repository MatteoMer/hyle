use anyhow::{anyhow, Error, Result};
use bincode::{Decode, Encode};
use hyle_contract_sdk::{BlobIndex, ContractName, TxHash};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ops::Deref, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::{
    bus::BusMessage,
    data_availability::{node_state::NodeState, DataEvent},
    model::{
        Blob, BlobTransaction, Block, CommonRunContext, Hashable, RegisterContractTransaction,
        Transaction, TransactionData,
    },
    module_handle_messages,
    utils::{conf::Conf, modules::Module},
};

use super::{contract_handlers::ContractHandler, indexer_bus_client::IndexerBusClient};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ProverEvent {
    NewTx(Transaction),
}
impl BusMessage for ProverEvent {}

#[derive(Encode, Decode)]
pub struct Store<State> {
    pub state: Option<State>,
    pub contract_name: ContractName,
    pub unsettled_blobs: BTreeMap<TxHash, BlobTransaction>,
    pub node_state: NodeState,
}

impl<State> Default for Store<State> {
    fn default() -> Self {
        Store {
            state: None,
            contract_name: Default::default(),
            unsettled_blobs: BTreeMap::new(),
            node_state: NodeState::default(),
        }
    }
}

pub struct ContractStateIndexer<State> {
    bus: IndexerBusClient,
    store: Arc<RwLock<Store<State>>>,
    contract_name: ContractName,
    file: PathBuf,
    config: Arc<Conf>,
}

pub struct ContractStateIndexerCtx {
    pub common: Arc<CommonRunContext>,
    pub contract_name: ContractName,
}

impl<State> Module for ContractStateIndexer<State>
where
    State: Serialize
        + TryFrom<hyle_contract_sdk::StateDigest, Error = Error>
        + Clone
        + Sync
        + Send
        + ContractHandler
        + Encode
        + Decode
        + 'static,
{
    type Context = ContractStateIndexerCtx;

    async fn build(ctx: Self::Context) -> Result<Self> {
        let bus = IndexerBusClient::new_from_bus(ctx.common.bus.new_handle()).await;
        let file = ctx
            .common
            .config
            .data_directory
            .join(format!("state_indexer_{}.bin", ctx.contract_name).as_str());

        let mut store = Self::load_from_disk_or_default::<Store<State>>(file.as_path());
        store.contract_name = ctx.contract_name.clone();
        let store = Arc::new(RwLock::new(store));

        let api = State::api(Arc::clone(&store)).await;
        if let Ok(mut guard) = ctx.common.router.lock() {
            if let Some(router) = guard.take() {
                guard.replace(router.nest(
                    format!("/v1/indexer/contract/{}", ctx.contract_name).as_str(),
                    api,
                ));
            }
        }
        let config = ctx.common.config.clone();

        Ok(ContractStateIndexer {
            bus,
            config,
            file,
            store,
            contract_name: ctx.contract_name,
        })
    }

    fn run(&mut self) -> impl futures::Future<Output = Result<()>> + Send {
        self.start()
    }
}

impl<State> ContractStateIndexer<State>
where
    State: Serialize
        + TryFrom<hyle_contract_sdk::StateDigest, Error = Error>
        + Clone
        + Sync
        + Send
        + ContractHandler
        + Encode
        + Decode
        + 'static,
{
    pub async fn start(&mut self) -> Result<(), Error> {
        module_handle_messages! {
        on_bus self.bus,
        listen<DataEvent> cmd => {
            if let Err(e) = self.handle_data_availability_event(cmd).await {
                error!(cn = %self.contract_name, "Error while handling data availability event: {:#}", e)
            }
        }
        }

        if let Err(e) = Self::save_on_disk::<Store<State>>(
            self.config.data_directory.as_path(),
            self.file.as_path(),
            self.store.read().await.deref(),
        ) {
            tracing::warn!(cn = %self.contract_name, "Failed to save contract state indexer on disk: {}", e);
        }
        Ok(())
    }

    /// Note: Each copy of the contract state indexer does the same handle_block on each data event
    /// coming from data availability. In a future refacto, data availability will stream handled blocks instead
    /// thus we could refacto this part too to avoid same processing in NodeState in each indexer
    async fn handle_data_availability_event(&mut self, event: DataEvent) -> Result<(), Error> {
        if let DataEvent::NewBlock(block) = event {
            self.handle_processed_block(*block).await?;
        }

        Ok(())
    }

    async fn handle_processed_block(&mut self, block: Block) -> Result<()> {
        info!(
            cn = %self.contract_name, "📦 Handling block #{}",
            block.block_height,
        );
        debug!(cn = %self.contract_name, "📦 Handled block outputs: {:?}", block);

        for c_tx in block.new_contract_txs {
            if let TransactionData::RegisterContract(tx) = c_tx.transaction_data {
                self.handle_register_contract(tx).await?;
            }
        }

        for b_tx in block.new_blob_txs {
            if let TransactionData::Blob(tx) = b_tx.transaction_data {
                self.handle_blob(tx).await?;
            }
        }

        for s_tx in block.settled_blob_tx_hashes {
            self.settle_tx(s_tx).await?;
        }
        Ok(())
    }

    async fn handle_register_contract(&mut self, tx: RegisterContractTransaction) -> Result<()> {
        if tx.contract_name != self.contract_name {
            return Ok(());
        }
        info!(cn = %self.contract_name, "📝 Registering supported contract '{}'", tx.contract_name);
        let state = tx.state_digest.try_into()?;
        self.store.write().await.state = Some(state);
        Ok(())
    }

    async fn handle_blob(&mut self, tx: BlobTransaction) -> Result<()> {
        let tx_hash = tx.hash();
        let mut found_supported_blob = false;

        for b in &tx.blobs {
            if self.contract_name == b.contract_name {
                found_supported_blob = true;
                break;
            }
        }

        if found_supported_blob {
            info!(cn = %self.contract_name, "⚒️  Found supported blob in transaction: {}", tx_hash);
            self.store
                .write()
                .await
                .unsettled_blobs
                .insert(tx_hash.clone(), tx);
        }

        Ok(())
    }

    async fn settle_tx(&mut self, tx: TxHash) -> Result<()> {
        let mut store = self.store.write().await;
        let Some(tx) = store.unsettled_blobs.remove(&tx) else {
            debug!(cn = %self.contract_name, "🔨 No supported blobs found in transaction: {}", tx);
            return Ok(());
        };

        info!(cn = %self.contract_name, "🔨 Settling transaction: {}", tx.hash());

        for (index, Blob { contract_name, .. }) in tx.blobs.iter().enumerate() {
            if self.contract_name != *contract_name {
                continue;
            }

            let state = store
                .state
                .clone()
                .ok_or(anyhow!("No state found for {contract_name}"))?;

            let new_state = State::handle(&tx, BlobIndex(index), state)?;

            info!(cn = %self.contract_name, "📈 Updated state for {contract_name}");

            store.state = Some(new_state);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hyle_contract_sdk::{BlobData, ProgramId, StateDigest};

    use super::*;
    use crate::bus::metrics::BusMetrics;
    use crate::model::{BlockHash, BlockHeight};
    use crate::utils::conf::Conf;
    use crate::{bus::SharedMessageBus, model::CommonRunContext};
    use std::sync::Arc;

    #[derive(Clone, Debug, Default, Encode, Decode, Serialize, Deserialize)]
    struct MockState(Vec<u8>);

    impl TryFrom<StateDigest> for MockState {
        type Error = Error;

        fn try_from(value: StateDigest) -> Result<Self> {
            Ok(MockState(value.0))
        }
    }

    impl ContractHandler for MockState {
        fn handle(tx: &BlobTransaction, index: BlobIndex, mut state: Self) -> Result<Self> {
            state.0 = tx.blobs.get(index.0).unwrap().data.0.clone();
            Ok(state)
        }

        async fn api(_store: Arc<RwLock<Store<Self>>>) -> axum::Router<()> {
            axum::Router::new()
        }
    }

    async fn build_indexer(contract_name: ContractName) -> ContractStateIndexer<MockState> {
        let common = Arc::new(CommonRunContext {
            bus: SharedMessageBus::new(BusMetrics::global("global".to_string())),
            config: Arc::new(Conf::default()),
            router: Default::default(),
        });

        let ctx = ContractStateIndexerCtx {
            common: common.clone(),
            contract_name,
        };

        ContractStateIndexer::<MockState>::build(ctx).await.unwrap()
    }

    async fn register_contract(indexer: &mut ContractStateIndexer<MockState>) {
        let state_digest = StateDigest(vec![]);
        let tx = RegisterContractTransaction {
            contract_name: indexer.contract_name.clone(),
            state_digest,
            owner: "onwer".into(),
            verifier: "test".into(),
            program_id: ProgramId(vec![]),
        };
        indexer.handle_register_contract(tx).await.unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn test_handle_register_contract() {
        let contract_name = ContractName::from("test_contract");
        let mut indexer = build_indexer(contract_name.clone()).await;

        let state_digest = StateDigest::default();
        let tx = RegisterContractTransaction {
            contract_name: contract_name.clone(),
            state_digest,
            owner: "onwer".into(),
            verifier: "test".into(),
            program_id: ProgramId(vec![]),
        };
        indexer.handle_register_contract(tx).await.unwrap();

        let store = indexer.store.read().await;
        assert!(store.state.is_some());
    }

    #[test_log::test(tokio::test)]
    async fn test_handle_blob() {
        let contract_name = ContractName::from("test_contract");
        let blob = Blob {
            contract_name: contract_name.clone(),
            data: BlobData(vec![1, 2, 3]),
        };
        let tx = BlobTransaction {
            blobs: vec![blob],
            identity: "test".into(),
        };
        let tx_hash = tx.hash();

        let mut indexer = build_indexer(contract_name.clone()).await;
        register_contract(&mut indexer).await;
        indexer.handle_blob(tx).await.unwrap();

        let store = indexer.store.read().await;
        assert!(store.unsettled_blobs.contains_key(&tx_hash));
        assert!(store.state.clone().unwrap().0.is_empty());
    }

    #[test_log::test(tokio::test)]
    async fn test_settle_tx() {
        let contract_name = ContractName::from("test_contract");
        let blob = Blob {
            contract_name: contract_name.clone(),
            data: BlobData(vec![1, 2, 3]),
        };
        let tx = BlobTransaction {
            blobs: vec![blob],
            identity: "test".into(),
        };
        let tx_hash = tx.hash();

        let mut indexer = build_indexer(contract_name.clone()).await;
        register_contract(&mut indexer).await;
        {
            let mut store = indexer.store.write().await;
            store.unsettled_blobs.insert(tx_hash.clone(), tx);
        }

        indexer.settle_tx(tx_hash.clone()).await.unwrap();

        let store = indexer.store.read().await;
        assert!(!store.unsettled_blobs.contains_key(&tx_hash));
        assert_eq!(store.state.clone().unwrap().0, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_handle_data_availability_event() {
        let contract_name = ContractName::from("test_contract");
        let mut indexer = build_indexer(contract_name.clone()).await;
        register_contract(&mut indexer).await;

        let mut node_state = NodeState::default();
        let block = node_state.handle_new_cut(
            BlockHeight(1),
            BlockHash::new("0123456789abcdef"),
            1,
            vec![],
            vec![],
        );

        let event = DataEvent::NewBlock(Box::new(block));

        indexer.handle_data_availability_event(event).await.unwrap();
        // Add assertions based on the expected state changes
    }
}