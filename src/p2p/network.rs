use crate::model::Transaction;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Version {
    pub id: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum NetMessage {
    Version(Version),
    Verack,
    Ping,
    Pong,
    // TODO: To replace with an ApiMessage equivalent
    NewTransaction(Transaction),
    MempoolMessage(MempoolMessage),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MempoolMessage {
    NewTx(Transaction),
}

impl NetMessage {
    pub fn to_binary(&self) -> Vec<u8> {
        bincode::serialize(&self).expect("Could not serialize NetMessage")
    }
}