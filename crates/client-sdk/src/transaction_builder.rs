use std::{collections::BTreeMap, pin::Pin, sync::OnceLock};

use anyhow::Result;

use sdk::{
    info, Blob, BlobData, BlobIndex, ContractAction, ContractInput, ContractName, HyleOutput,
    Identity, StateDigest,
};

use crate::{helpers, BlobTransaction, Hashable, ProofData};

pub struct BuildResult {
    pub identity: Identity,
    pub blobs: Vec<Blob>,
    pub outputs: Vec<(ContractName, HyleOutput)>,
}

pub struct TransactionBuilder {
    pub identity: Identity,
    runners: Vec<ContractRunner>,
    pub blobs: Vec<Blob>,
    on_chain_states: BTreeMap<ContractName, StateDigest>,
}

pub trait StateUpdater {
    fn update(&mut self, contract_name: &ContractName, new_state: StateDigest) -> Result<()>;
    fn get(&self, contract_name: &ContractName) -> Result<StateDigest>;
}

impl TransactionBuilder {
    pub fn new(identity: Identity) -> Self {
        TransactionBuilder {
            identity,
            runners: vec![],
            blobs: vec![],
            on_chain_states: BTreeMap::new(),
        }
    }

    pub fn init_with(&mut self, contract_name: ContractName, state: StateDigest) {
        self.on_chain_states.entry(contract_name).or_insert(state);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_action<CF: ContractAction>(
        &mut self,
        contract_name: ContractName,
        binary: &'static [u8],
        prover: helpers::Prover,
        action: CF,
        caller: Option<BlobIndex>,
        callees: Option<Vec<BlobIndex>>,
    ) -> Result<&'_ mut ContractRunner> {
        let runner = ContractRunner::new(
            contract_name.clone(),
            binary,
            prover,
            self.identity.clone(),
            BlobIndex(self.blobs.len()),
        )?;
        self.runners.push(runner);
        self.blobs
            .push(action.as_blob(contract_name, caller, callees));
        Ok(self.runners.last_mut().unwrap())
    }

    pub fn build<S: StateUpdater>(&mut self, full_states: &mut S) -> Result<BuildResult> {
        let mut outputs = vec![];
        for runner in self.runners.iter_mut() {
            let on_chain_state = self
                .on_chain_states
                .get(&runner.contract_name)
                .cloned()
                .ok_or(anyhow::anyhow!("State not found"))?;
            let full_state = full_states.get(&runner.contract_name)?.clone();

            let private_blob = runner.private_blob(full_state.clone())?;

            runner.build_input(self.blobs.clone(), private_blob, on_chain_state.clone());

            let out = runner.execute()?;
            self.on_chain_states
                .entry(runner.contract_name.clone())
                .and_modify(|v| *v = out.next_state.clone());

            if let Some(off_chain_new_state) = runner.callback(full_state)? {
                full_states.update(&runner.contract_name, off_chain_new_state)?;
            } else {
                full_states.update(&runner.contract_name, out.next_state.clone())?;
            }

            outputs.push((runner.contract_name.clone(), out));
        }

        Ok(BuildResult {
            identity: self.identity.clone(),
            blobs: self.blobs.clone(),
            outputs,
        })
    }

    /// Returns an iterator over the proofs of the transactions
    /// In order to send proofs when they are ready, without waiting for all of them to be ready
    /// Example usage:
    /// for (proof, contract_name) in transaction.iter_prove() {
    ///    let proof: ProofData = proof.await.unwrap();
    ///    ctx.client()
    ///        .send_tx_proof(&hyle::model::ProofTransaction {
    ///            blob_tx_hash: blob_tx_hash.clone(),
    ///            proof,
    ///            contract_name,
    ///        })
    ///        .await
    ///        .unwrap();
    ///}
    pub fn iter_prove<'a>(
        &'a self,
    ) -> impl Iterator<
        Item = (
            Pin<Box<dyn std::future::Future<Output = Result<ProofData>> + Send + 'a>>,
            ContractName,
        ),
    > + 'a {
        self.runners.iter().map(|runner| {
            let future = runner.prove();
            (
                Box::pin(future)
                    as Pin<Box<dyn std::future::Future<Output = Result<ProofData>> + Send + 'a>>,
                runner.contract_name.clone(),
            )
        })
    }
}

pub struct ContractRunner {
    pub contract_name: ContractName,
    identity: Identity,
    index: BlobIndex,
    binary: &'static [u8],
    prover: helpers::Prover,
    contract_input: OnceLock<ContractInput>,
    offchain_cb: Option<Box<dyn Fn(StateDigest) -> Result<StateDigest> + Send + Sync>>,
    private_blob_cb: Option<Box<dyn Fn(StateDigest) -> Result<BlobData> + Send + Sync>>,
}

impl ContractRunner {
    fn new(
        contract_name: ContractName,
        binary: &'static [u8],
        prover: helpers::Prover,
        identity: Identity,
        index: BlobIndex,
    ) -> Result<Self> {
        Ok(Self {
            contract_name,
            binary,
            prover,
            identity,
            index,
            contract_input: OnceLock::new(),
            offchain_cb: None,
            private_blob_cb: None,
        })
    }

    pub fn build_offchain_state<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(StateDigest) -> Result<StateDigest> + Send + Sync + 'static,
    {
        self.offchain_cb = Some(Box::new(f));
        self
    }

    pub fn with_private_blob<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(StateDigest) -> Result<BlobData> + Send + Sync + 'static,
    {
        self.private_blob_cb = Some(Box::new(f));
        self
    }

    fn callback(&self, state: StateDigest) -> Result<Option<StateDigest>> {
        self.offchain_cb
            .as_ref()
            .map(|cb| cb(state))
            .map_or(Ok(None), |v| v.map(Some))
    }

    fn private_blob(&self, state: StateDigest) -> Result<BlobData> {
        self.private_blob_cb
            .as_ref()
            .map(|cb| cb(state))
            .map_or(Ok(BlobData::default()), |v| v)
    }

    fn build_input(
        &mut self,
        blobs: Vec<Blob>,
        private_blob: BlobData,
        initial_state: StateDigest,
    ) {
        let tx_hash = BlobTransaction {
            identity: self.identity.clone(),
            blobs: blobs.clone(),
        }
        .hash();

        self.contract_input.get_or_init(|| ContractInput {
            identity: self.identity.clone(),
            tx_hash,
            blobs,
            private_blob,
            index: self.index.clone(),
            initial_state,
        });
    }

    fn execute(&self) -> Result<HyleOutput> {
        info!("Checking transition for {}...", self.contract_name);

        self.prover
            .execute(self.binary, self.contract_input.get().unwrap())
    }

    async fn prove(&self) -> Result<ProofData> {
        info!("Proving transition for {}...", self.contract_name);

        let (proof, _) = self
            .prover
            .prove(self.binary, self.contract_input.get().unwrap())
            .await?;
        Ok(proof)
    }
}
