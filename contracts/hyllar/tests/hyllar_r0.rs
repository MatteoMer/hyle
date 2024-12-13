use core::str;

use hyllar::HyllarToken;
use sdk::{erc20::ERC20Action, BlobData, BlobIndex, ContractInput, ContractName, HyleOutput};
static HYLLAR_BIN: &[u8] = include_bytes!("../hyllar.img");

fn execute(inputs: ContractInput<HyllarToken>) -> HyleOutput {
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(&inputs)
        .unwrap()
        .build()
        .unwrap();
    let prover = risc0_zkvm::default_executor();
    let execute_info = prover.execute(env, HYLLAR_BIN).unwrap();

    execute_info.journal.decode::<sdk::HyleOutput>().unwrap()
}

#[test]
fn execute_transfer_from() {
    let output = execute(ContractInput::<HyllarToken> {
        initial_state: HyllarToken::new(1000, "faucet".to_string()),
        identity: "caller".into(),
        tx_hash: "".into(),
        private_blob: BlobData(vec![]),
        blobs: vec![ERC20Action::TransferFrom {
            sender: "faucet".into(),
            recipient: "amm".into(),
            amount: 100,
        }
        .as_blob(ContractName("hyllar".to_owned()), None, None)],
        index: BlobIndex(0),
    });

    assert!(!output.success);
    assert_eq!(
        str::from_utf8(&output.program_outputs).unwrap(),
        "Allowance exceeded for sender=faucet caller=caller allowance=0"
    );
}