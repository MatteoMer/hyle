//! Various data structures

#[cfg(feature = "node")]
use crate::bus::SharedMessageBus;
#[cfg(feature = "node")]
use crate::utils::{conf::SharedConf, crypto::SharedBlstCrypto};
#[cfg(feature = "node")]
use axum::Router;
use data_availability::HandledBlobProofOutput;
use std::collections::HashSet;
#[cfg(feature = "node")]
use std::sync::Arc;

use bincode::{Decode, Encode};
pub use client_sdk::{BlobTransaction, BlobsHash, Hashable, ProofData, ProofDataHash};
use derive_more::Display;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fmt,
    ops::Add,
    time::{SystemTime, UNIX_EPOCH},
};
use strum_macros::IntoStaticStr;

use consensus::{ConsensusProposal, ConsensusProposalHash};
use crypto::AggregateSignature;
use hyle_contract_sdk::{
    BlobIndex, HyleOutput, Identity, ProgramId, StateDigest, TxHash, Verifier,
};
use mempool::DataProposal;
use staking::StakingAction;

// Re-export
pub use hyle_contract_sdk::{Blob, BlobData, ContractName};
pub use staking::model::ValidatorPublicKey;

pub mod consensus;
pub mod crypto;
pub mod data_availability;
pub mod indexer;
pub mod mempool;
pub mod rest;

pub const HASH_DISPLAY_SIZE: usize = 3;

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    Hash,
    Display,
    Copy,
    Encode,
    Decode,
)]
pub struct BlockHeight(pub u64);

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Transaction {
    pub version: u32,
    pub transaction_data: TransactionData,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Encode, Decode, IntoStaticStr)]
pub enum TransactionData {
    Blob(BlobTransaction),
    Proof(ProofTransaction),
    VerifiedProof(VerifiedProofTransaction),
    RegisterContract(RegisterContractTransaction),
}

impl Default for TransactionData {
    fn default() -> Self {
        TransactionData::Blob(BlobTransaction::default())
    }
}

#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Clone, Encode, Decode)]
pub struct ProofTransaction {
    pub contract_name: ContractName,
    pub proof: ProofData,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlobProofOutput {
    // TODO: this can be recovered from the hyle output
    pub blob_tx_hash: TxHash,
    // TODO: remove this?
    pub original_proof_hash: ProofDataHash,

    /// HyleOutput of the proof for this blob
    pub hyle_output: HyleOutput,
    /// Program ID used to verify the proof.
    pub program_id: ProgramId,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Encode, Decode)]
pub struct VerifiedProofTransaction {
    pub contract_name: ContractName,
    pub proof: Option<ProofData>, // Kept only on the local lane for indexing purposes
    pub proof_hash: ProofDataHash,
    pub proven_blobs: Vec<BlobProofOutput>,
    pub is_recursive: bool,
}

impl fmt::Debug for VerifiedProofTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedProofTransaction")
            .field("contract_name", &self.contract_name)
            .field("proof_hash", &self.proof_hash)
            .field("proof", &"[HIDDEN]")
            .field(
                "proof_len",
                &match &self.proof {
                    Some(ProofData::Base64(v)) => v.len(),
                    Some(ProofData::Bytes(v)) => v.len(),
                    None => 0,
                },
            )
            .field("proven_blobs", &self.proven_blobs)
            .finish()
    }
}

impl fmt::Debug for ProofTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProofTransaction")
            .field("contract_name", &self.contract_name)
            .field("proof", &"[HIDDEN]")
            .field(
                "proof_len",
                &self.proof.to_bytes().unwrap_or_default().len(),
            )
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq, Encode, Decode)]
pub struct RegisterContractTransaction {
    pub owner: String,
    pub verifier: Verifier,
    pub program_id: ProgramId,
    pub state_digest: StateDigest,
    pub contract_name: ContractName,
}

impl Transaction {
    pub fn wrap(data: TransactionData) -> Self {
        Transaction {
            version: 1,
            transaction_data: data,
        }
    }
}

impl From<BlobTransaction> for Transaction {
    fn from(tx: BlobTransaction) -> Self {
        Transaction::wrap(TransactionData::Blob(tx))
    }
}

impl From<ProofTransaction> for Transaction {
    fn from(tx: ProofTransaction) -> Self {
        Transaction::wrap(TransactionData::Proof(tx))
    }
}

impl From<VerifiedProofTransaction> for Transaction {
    fn from(tx: VerifiedProofTransaction) -> Self {
        Transaction::wrap(TransactionData::VerifiedProof(tx))
    }
}

impl From<RegisterContractTransaction> for Transaction {
    fn from(tx: RegisterContractTransaction) -> Self {
        Transaction::wrap(TransactionData::RegisterContract(tx))
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode, Eq, PartialEq)]
pub struct Block {
    pub parent_hash: ConsensusProposalHash,
    pub hash: ConsensusProposalHash,
    pub block_height: BlockHeight,
    pub block_timestamp: u64,
    pub txs: Vec<Transaction>,
    pub failed_txs: HashSet<TxHash>,
    pub blob_proof_outputs: Vec<HandledBlobProofOutput>,
    pub settled_blob_tx_hashes: Vec<TxHash>,
    pub verified_blobs: Vec<(TxHash, BlobIndex, usize)>,
    pub new_bounded_validators: Vec<ValidatorPublicKey>,
    pub staking_actions: Vec<(Identity, StakingAction)>,
    pub timed_out_tx_hashes: Vec<TxHash>,
    pub updated_states: BTreeMap<ContractName, StateDigest>,
}

impl Block {
    pub fn total_txs(&self) -> usize {
        self.txs.len()
    }
}

impl Ord for Block {
    fn cmp(&self, other: &Self) -> Ordering {
        self.block_height.0.cmp(&other.block_height.0)
    }
}

impl PartialOrd for Block {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Encode, Decode, Display)]
#[display("")]
pub struct SignedBlock {
    pub data_proposals: Vec<(ValidatorPublicKey, Vec<DataProposal>)>,
    pub certificate: AggregateSignature,
    pub consensus_proposal: ConsensusProposal,
}

impl SignedBlock {
    pub fn parent_hash(&self) -> &ConsensusProposalHash {
        &self.consensus_proposal.parent_hash
    }

    pub fn height(&self) -> BlockHeight {
        BlockHeight(self.consensus_proposal.slot)
    }

    pub fn txs(&self) -> Vec<Transaction> {
        self.data_proposals
            .iter()
            .flat_map(|(_, dps)| dps)
            .flat_map(|dp| dp.txs.clone())
            .collect()
    }
}

impl Ord for SignedBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        self.height().0.cmp(&other.height().0)
    }
}

impl PartialOrd for SignedBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SignedBlock {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for SignedBlock {}

pub struct HyleOutputHash(pub Vec<u8>);
pub struct BlobProofOutputHash(pub Vec<u8>);

impl Hashable<HyleOutputHash> for HyleOutput {
    fn hash(&self) -> HyleOutputHash {
        let mut hasher = Sha3_256::new();
        hasher.update(self.version.to_le_bytes());
        hasher.update(self.initial_state.0.clone());
        hasher.update(self.next_state.0.clone());
        hasher.update(self.identity.0.as_bytes());
        hasher.update(self.tx_hash.0.as_bytes());
        hasher.update(self.index.0.to_le_bytes());
        hasher.update(&self.blobs);
        hasher.update([self.success as u8]);
        hasher.update(&self.program_outputs);
        HyleOutputHash(hasher.finalize().to_vec())
    }
}

impl Hashable<BlobProofOutputHash> for BlobProofOutput {
    fn hash(&self) -> BlobProofOutputHash {
        let mut hasher = Sha3_256::new();
        hasher.update(self.blob_tx_hash.0.as_bytes());
        hasher.update(self.original_proof_hash.0.as_bytes());
        hasher.update(self.program_id.0.clone());
        hasher.update(self.hyle_output.hash().0);
        BlobProofOutputHash(hasher.finalize().to_vec())
    }
}

// TODO: Return consensus proposal hash
impl Hashable<ConsensusProposalHash> for SignedBlock {
    fn hash(&self) -> ConsensusProposalHash {
        self.consensus_proposal.hash()
    }
}

impl Hashable<TxHash> for Transaction {
    fn hash(&self) -> TxHash {
        match &self.transaction_data {
            TransactionData::Blob(tx) => tx.hash(),
            TransactionData::Proof(tx) => tx.hash(),
            TransactionData::VerifiedProof(tx) => tx.hash(),
            TransactionData::RegisterContract(tx) => tx.hash(),
        }
    }
}

impl Hashable<TxHash> for ProofTransaction {
    fn hash(&self) -> TxHash {
        let mut hasher = Sha3_256::new();
        hasher.update(self.contract_name.0.as_bytes());
        hasher.update(self.proof.hash().0);
        let hash_bytes = hasher.finalize();
        TxHash(hex::encode(hash_bytes))
    }
}
impl Hashable<TxHash> for VerifiedProofTransaction {
    fn hash(&self) -> TxHash {
        let mut hasher = Sha3_256::new();
        hasher.update(self.contract_name.0.as_bytes());
        hasher.update(self.proof_hash.0.as_bytes());
        hasher.update(self.proven_blobs.len().to_le_bytes());
        for proven_blob in self.proven_blobs.iter() {
            hasher.update(proven_blob.hash().0);
        }
        let hash_bytes = hasher.finalize();
        TxHash(hex::encode(hash_bytes))
    }
}
impl Hashable<TxHash> for RegisterContractTransaction {
    fn hash(&self) -> TxHash {
        let mut hasher = Sha3_256::new();
        hasher.update(self.owner.clone());
        hasher.update(self.verifier.0.clone());
        hasher.update(self.program_id.0.clone());
        hasher.update(self.state_digest.0.clone());
        hasher.update(self.contract_name.0.clone());
        let hash_bytes = hasher.finalize();
        TxHash(hex::encode(hash_bytes))
    }
}

impl std::default::Default for SignedBlock {
    fn default() -> Self {
        SignedBlock {
            consensus_proposal: ConsensusProposal::default(),
            data_proposals: vec![],
            certificate: AggregateSignature {
                signature: crypto::Signature("signature".into()),
                validators: vec![],
            },
        }
    }
}

impl Add<BlockHeight> for u64 {
    type Output = BlockHeight;
    fn add(self, other: BlockHeight) -> BlockHeight {
        BlockHeight(self + other.0)
    }
}

impl Add<u64> for BlockHeight {
    type Output = BlockHeight;
    fn add(self, other: u64) -> BlockHeight {
        BlockHeight(self.0 + other)
    }
}

impl Add<BlockHeight> for BlockHeight {
    type Output = BlockHeight;
    fn add(self, other: BlockHeight) -> BlockHeight {
        BlockHeight(self.0 + other.0)
    }
}

pub fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

pub fn get_current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

#[cfg(feature = "node")]
pub struct CommonRunContext {
    pub config: SharedConf,
    pub bus: SharedMessageBus,
    pub router: std::sync::Mutex<Option<Router>>,
}

#[cfg(feature = "node")]
pub struct NodeRunContext {
    pub crypto: SharedBlstCrypto,
}

#[cfg(feature = "node")]
#[derive(Clone)]
pub struct SharedRunContext {
    pub common: Arc<CommonRunContext>,
    pub node: Arc<NodeRunContext>,
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::model::BlockHeight;

    proptest! {
        #[test]
        fn block_height_add(x in 0u64..10000, y in 0u64..10000) {
            let b = BlockHeight(x);
            let c = BlockHeight(y);

            assert_eq!((b + c).0, (c + b).0);
            assert_eq!((b + y).0, x + y);
            assert_eq!((y + b).0, x + y);
        }
    }
}
