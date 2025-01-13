use std::collections::BTreeMap;
use std::fmt::Write;
use std::io::Read;

use anyhow::{bail, Context, Error};
use rand::Rng;
use reclaim_rust_sdk::verify_proof as reclaim_verify_proof;
use risc0_recursion::{Risc0Journal, Risc0ProgramId};
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1VerifyingKey};

use hyle_contract_sdk::{HyleOutput, ProgramId, Verifier};

pub fn verify_proof(
    proof: &[u8],
    verifier: &Verifier,
    program_id: &ProgramId,
) -> Result<Vec<HyleOutput>, Error> {
    let hyle_outputs = match verifier.0.as_str() {
        // TODO: add #[cfg(test)]
        "test" => Ok(serde_json::from_slice(proof)?),
        #[cfg(test)]
        "test-slow" => {
            tracing::info!("Sleeping for 2 seconds to simulate a slow verifier");
            std::thread::sleep(std::time::Duration::from_secs(2));
            tracing::info!("Woke up from sleep");
            Ok(serde_json::from_slice(proof)?)
        }
        "risc0" => {
            let journal = risc0_proof_verifier(proof, &program_id.0)?;
            // First try to decode it as a single HyleOutput
            Ok(match journal.decode::<HyleOutput>() {
                Ok(ho) => vec![ho],
                Err(_) => {
                    let hyle_output = journal
                        .decode::<Vec<Vec<u8>>>()
                        .context("Failed to extract HyleOuput from Risc0's journal")?;

                    // Doesn't actually work to just deserialize in one go.
                    hyle_output
                        .iter()
                        .map(|o| risc0_zkvm::serde::from_slice::<HyleOutput, _>(o))
                        .collect::<Result<Vec<_>, _>>()
                        .context("Failed to decode HyleOutput")?
                }
            })
        }
        "noir" => noir_proof_verifier(proof, &program_id.0),
        "sp1" => sp1_proof_verifier(proof, &program_id.0),
        "reclaim" => reclaim_proof_verifier(proof, &program_id.0),
        _ => bail!("{} recursive verifier not implemented yet", verifier),
    }?;
    hyle_outputs.iter().for_each(|hyle_output| {
        tracing::info!(
            "🔎 {}",
            std::str::from_utf8(&hyle_output.program_outputs)
                .map(|o| format!("Program outputs: {o}"))
                .unwrap_or("Invalid UTF-8".to_string())
        );
    });

    Ok(hyle_outputs)
}

pub fn verify_recursive_proof(
    proof: &[u8],
    verifier: &Verifier,
    program_id: &ProgramId,
) -> Result<(Vec<ProgramId>, Vec<HyleOutput>), Error> {
    let outputs = match verifier.0.as_str() {
        "risc0" => {
            let journal = risc0_proof_verifier(proof, &program_id.0)?;
            let mut output = journal
                .decode::<Vec<(Risc0ProgramId, Risc0Journal)>>()
                .context("Failed to extract HyleOuput from Risc0's journal")?;

            // Doesn't actually work to just deserialize in one go.
            output
                .drain(..)
                .map(|o| {
                    risc0_zkvm::serde::from_slice::<HyleOutput, _>(&o.1)
                        .map(|h| (ProgramId(o.0.to_vec()), h))
                })
                .collect::<Result<(Vec<_>, Vec<_>), _>>()
                .context("Failed to decode HyleOutput")
        }
        _ => bail!("{} recursive verifier not implemented yet", verifier),
    }?;
    outputs.1.iter().for_each(|hyle_output| {
        tracing::info!(
            "🔎 {}",
            std::str::from_utf8(&hyle_output.program_outputs)
                .map(|o| format!("Program outputs: {o}"))
                .unwrap_or("Invalid UTF-8".to_string())
        );
    });

    Ok(outputs)
}

pub fn risc0_proof_verifier(
    encoded_receipt: &[u8],
    image_id: &[u8],
) -> Result<risc0_zkvm::Journal, Error> {
    let receipt = borsh::from_slice::<risc0_zkvm::Receipt>(encoded_receipt)
        .context("Error while decoding Risc0 proof's receipt")?;

    let image_bytes: Digest = image_id.try_into().context("Invalid Risc0 image ID")?;

    receipt
        .verify(image_bytes)
        .context("Risc0 proof verification failed")?;

    tracing::info!("✅ Risc0 proof verified.");

    Ok(receipt.journal)
}

/// At present, we are using binary to facilitate the integration of the Noir verifier.
/// This is not meant to be a permanent solution.
pub fn noir_proof_verifier(proof: &[u8], image_id: &[u8]) -> Result<Vec<HyleOutput>, Error> {
    let mut rng = rand::thread_rng();
    let salt: [u8; 16] = rng.gen();
    let mut salt_hex = String::with_capacity(salt.len() * 2);
    for b in &salt {
        write!(salt_hex, "{:02x}", b).unwrap();
    }

    let proof_path = &format!("/tmp/noir-proof-{salt_hex}");
    let vk_path = &format!("/tmp/noir-vk-{salt_hex}");
    let output_path = &format!("/tmp/noir-output-{salt_hex}");

    // Write proof and publicKey to files
    std::fs::write(proof_path, proof)?;
    std::fs::write(vk_path, image_id)?;

    // Verifying proof
    let verification_output = std::process::Command::new("bb")
        .arg("verify")
        .arg("-p")
        .arg(proof_path)
        .arg("-k")
        .arg(vk_path)
        .output()?;

    if !verification_output.status.success() {
        bail!(
            "Noir proof verification failed: {}",
            String::from_utf8_lossy(&verification_output.stderr)
        );
    }

    // Extracting outputs
    let public_outputs_output = std::process::Command::new("bb")
        .arg("proof_as_fields")
        .arg("-p")
        .arg(proof_path)
        .arg("-k")
        .arg(vk_path)
        .arg("-o")
        .arg(output_path)
        .output()?;

    if !public_outputs_output.status.success() {
        bail!(
            "Could not extract output from Noir proof: {}",
            String::from_utf8_lossy(&verification_output.stderr)
        );
    }

    // Reading output
    let mut file = std::fs::File::open(output_path).expect("Failed to open output file");
    let mut output_json = String::new();
    file.read_to_string(&mut output_json)
        .expect("Failed to read output file content");

    let mut public_outputs: Vec<String> = serde_json::from_str(&output_json)?;
    // TODO: support multi-output proofs.
    let hyle_output = crate::utils::noir_utils::parse_noir_output(&mut public_outputs)?;

    // Delete proof_path, vk_path, output_path
    let _ = std::fs::remove_file(proof_path);
    let _ = std::fs::remove_file(vk_path);
    let _ = std::fs::remove_file(output_path);
    Ok(vec![hyle_output])
}

/// The following environment variables are used to configure the prover:
/// - `SP1_PROVER`: The type of prover to use. Must be one of `mock`, `local`, `cuda`, or `network`.
pub fn sp1_proof_verifier(
    proof_bin: &[u8],
    verification_key: &[u8],
) -> Result<Vec<HyleOutput>, Error> {
    // Setup the prover client.
    let client = ProverClient::from_env();

    let (proof, _) =
        bincode::decode_from_slice::<bincode::serde::Compat<SP1ProofWithPublicValues>, _>(
            proof_bin,
            bincode::config::legacy().with_fixed_int_encoding(),
        )
        .context("Error while decoding SP1 proof.")?;

    // Deserialize verification key from JSON
    let vk: SP1VerifyingKey =
        serde_json::from_slice(verification_key).context("Invalid SP1 image ID")?;

    // Verify the proof.
    client
        .verify(&proof.0, &vk)
        .context("SP1 proof verification failed")?;

    // TODO: support multi-output proofs.
    let (hyle_output, _) = bincode::decode_from_slice::<HyleOutput, _>(
        proof.0.public_values.as_slice(),
        bincode::config::legacy().with_fixed_int_encoding(),
    )
    .context("Failed to extract HyleOuput from SP1 proof")?;

    tracing::info!("✅ SP1 proof verified.",);

    Ok(vec![hyle_output])
}

#[derive(Serialize, Deserialize, Debug)]
struct ReclaimContext {
    #[serde(rename = "contextAddress")]
    context_address: String,
    #[serde(rename = "contextMessage")]
    context_message: String,
    #[serde(rename = "extractedParameters")]
    extracted_parameters: BTreeMap<String, String>,
    #[serde(rename = "providerHash")]
    provider_hash: String,
}

pub fn reclaim_proof_verifier(
    proof_bin: &[u8],
    verification_key: &[u8],
) -> Result<Vec<HyleOutput>, Error> {
    // 0x0a is \n, we remove a possible trailing \n
    let verification_key = if verification_key.ends_with(&[0x0a]) {
        &verification_key[..verification_key.len() - 1]
    } else {
        verification_key
    };
    let proof_str = String::from_utf8(proof_bin.into()).expect("Invalid UTF-8");

    let proof: reclaim_rust_sdk::Proof =
        serde_json::from_str(&proof_str).context("couldnt parse reclaim proof")?;

    let context: ReclaimContext = serde_json::from_str(&proof.claim_data.context)
        .context("could not deserialize context in reclaim proof")?;

    let reclaim_blob = hyle_contract_sdk::Blob {
        contract_name: "test_contract".into(),
        data: hyle_contract_sdk::BlobData(
            bincode::encode_to_vec(&context.extracted_parameters, bincode::config::standard())
                .context("Couldn't encode reclaim blob")?,
        ),
    };

    if verification_key != context.provider_hash.as_bytes() {
        return Err(Error::msg("Verification key does not match provider hash"));
    }

    // Verify the proof.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = rt
        .block_on(reclaim_verify_proof(&proof))
        .context("could not verify reclaim proof")?;

    tracing::info!("✅ Reclaim proof verified.",);

    // TODO: change with reclaim context
    Ok(vec![HyleOutput {
        version: 1,
        initial_state: hyle_contract_sdk::StateDigest(vec![0, 0, 0, 0]),
        next_state: hyle_contract_sdk::StateDigest(vec![0, 0, 0, 0]),
        identity: hyle_contract_sdk::Identity("test.identity".to_owned()),
        tx_hash: hyle_contract_sdk::TxHash("".to_owned()),
        index: hyle_contract_sdk::BlobIndex(0),
        blobs: bincode::encode_to_vec(reclaim_blob, bincode::config::standard())
            .context("could not convert blob to bytes")?,
        success: result,
        program_outputs: vec![],
    }])
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use hyle_contract_sdk::{
        StateDigest, {BlobIndex, HyleOutput, Identity, TxHash},
    };

    use super::{noir_proof_verifier, reclaim_proof_verifier};

    fn load_file_as_bytes(path: &str) -> Vec<u8> {
        let mut file = File::open(path).expect("Failed to open file");
        let mut encoded_receipt = Vec::new();
        file.read_to_end(&mut encoded_receipt)
            .expect("Failed to read file content");
        encoded_receipt
    }

    /*
        For this test, the proof/vk and the output are obtained running this simple Noir code
        ```
            fn main(
            version: pub u32,
            initial_state_len: pub u32,
            initial_state: pub [u8; 4],
            next_state_len: pub u32,
            next_state: pub [u8; 4],
            identity_len: pub u8,
            identity: pub str<56>,
            tx_hash_len: pub u32,
            tx_hash: pub [u8; 0],
            index: pub u32,
            blobs_len: pub u32,
            blobs: pub [Field; 10],
            success: pub bool
            ) {}
        ```
        With the values:
        ```
            version = 1
            blobs = [3, 1, 1, 2, 1, 1, 2, 1, 1, 0]
            initial_state_len = 4
            initial_state = [0, 0, 0, 0]
            next_state_len = 4
            next_state = [0, 0, 0, 0]
            identity_len = 56
            identity = "3f368bf90c71946fc7b0cde9161ace42985d235f.ecdsa_secp256r1"
            tx_hash_len = 0
            tx_hash = []
            blobs_len = 9
            index = 0
            success = 1
        ```
    */
    #[ignore = "manual test"]
    #[test_log::test]
    fn test_noir_proof_verifier() {
        let noir_proof = load_file_as_bytes("./tests/proofs/webauthn.noir.proof");
        let image_id = load_file_as_bytes("./tests/proofs/webauthn.noir.vk");

        let result = noir_proof_verifier(&noir_proof, &image_id);
        match result {
            Ok(outputs) => {
                assert_eq!(
                    outputs,
                    vec![HyleOutput {
                        version: 1,
                        initial_state: StateDigest(vec![0, 0, 0, 0]),
                        next_state: StateDigest(vec![0, 0, 0, 0]),
                        identity: Identity(
                            "3f368bf90c71946fc7b0cde9161ace42985d235f.ecdsa_secp256r1".to_owned()
                        ),
                        tx_hash: TxHash("".to_owned()),
                        index: BlobIndex(0),
                        blobs: vec![1, 1, 1, 1, 1],
                        success: true,
                        program_outputs: vec![]
                    }]
                );
            }
            Err(e) => panic!("Noir verification failed: {:?}", e),
        }
    }

    #[ignore = "manual test"]
    #[test_log::test]
    fn test_reclaim_proof_verifier() {
        let noir_proof = load_file_as_bytes("./tests/proofs/default.reclaim.proof");
        let image_id = load_file_as_bytes("./tests/proofs/default.reclaim.vk");

        let result = reclaim_proof_verifier(&noir_proof, &image_id);
        match result {
            Ok(outputs) => {
                assert_eq!(
                    outputs,
                    vec![HyleOutput {
                        version: 1,
                        initial_state: hyle_contract_sdk::StateDigest(vec![0, 0, 0, 0]),
                        next_state: hyle_contract_sdk::StateDigest(vec![0, 0, 0, 0]),
                        identity: "test.identity".into(),
                        tx_hash: "".into(),
                        index: BlobIndex(0),
                        blobs: [
                            13, 116, 101, 115, 116, 95, 99, 111, 110, 116, 114, 97, 99, 116, 251,
                            62, 9, 7, 12, 85, 82, 76, 95, 80, 65, 82, 65, 77, 83, 95, 49, 22, 71,
                            66, 83, 102, 68, 78, 66, 100, 90, 80, 82, 100, 74, 67, 102, 89, 100,
                            51, 109, 82, 55, 81, 12, 85, 82, 76, 95, 80, 65, 82, 65, 77, 83, 95,
                            50, 251, 78, 1, 37, 55, 66, 37, 50, 50, 102, 111, 99, 97, 108, 84, 119,
                            101, 101, 116, 73, 100, 37, 50, 50, 37, 51, 65, 37, 50, 50, 49, 55, 57,
                            56, 56, 49, 48, 50, 49, 51, 53, 50, 50, 53, 53, 48, 57, 52, 55, 37, 50,
                            50, 37, 50, 67, 37, 50, 50, 114, 101, 102, 101, 114, 114, 101, 114, 37,
                            50, 50, 37, 51, 65, 37, 50, 50, 109, 101, 37, 50, 50, 37, 50, 67, 37,
                            50, 50, 119, 105, 116, 104, 95, 114, 117, 120, 95, 105, 110, 106, 101,
                            99, 116, 105, 111, 110, 115, 37, 50, 50, 37, 51, 65, 102, 97, 108, 115,
                            101, 37, 50, 67, 37, 50, 50, 114, 97, 110, 107, 105, 110, 103, 77, 111,
                            100, 101, 37, 50, 50, 37, 51, 65, 37, 50, 50, 82, 101, 108, 101, 118,
                            97, 110, 99, 101, 37, 50, 50, 37, 50, 67, 37, 50, 50, 105, 110, 99,
                            108, 117, 100, 101, 80, 114, 111, 109, 111, 116, 101, 100, 67, 111,
                            110, 116, 101, 110, 116, 37, 50, 50, 37, 51, 65, 116, 114, 117, 101,
                            37, 50, 67, 37, 50, 50, 119, 105, 116, 104, 67, 111, 109, 109, 117,
                            110, 105, 116, 121, 37, 50, 50, 37, 51, 65, 116, 114, 117, 101, 37, 50,
                            67, 37, 50, 50, 119, 105, 116, 104, 81, 117, 105, 99, 107, 80, 114,
                            111, 109, 111, 116, 101, 69, 108, 105, 103, 105, 98, 105, 108, 105,
                            116, 121, 84, 119, 101, 101, 116, 70, 105, 101, 108, 100, 115, 37, 50,
                            50, 37, 51, 65, 116, 114, 117, 101, 37, 50, 67, 37, 50, 50, 119, 105,
                            116, 104, 66, 105, 114, 100, 119, 97, 116, 99, 104, 78, 111, 116, 101,
                            115, 37, 50, 50, 37, 51, 65, 116, 114, 117, 101, 37, 50, 67, 37, 50,
                            50, 119, 105, 116, 104, 86, 111, 105, 99, 101, 37, 50, 50, 37, 51, 65,
                            116, 114, 117, 101, 37, 55, 68, 12, 85, 82, 76, 95, 80, 65, 82, 65, 77,
                            83, 95, 51, 251, 142, 5, 37, 55, 66, 37, 50, 50, 112, 114, 111, 102,
                            105, 108, 101, 95, 108, 97, 98, 101, 108, 95, 105, 109, 112, 114, 111,
                            118, 101, 109, 101, 110, 116, 115, 95, 112, 99, 102, 95, 108, 97, 98,
                            101, 108, 95, 105, 110, 95, 112, 111, 115, 116, 95, 101, 110, 97, 98,
                            108, 101, 100, 37, 50, 50, 37, 51, 65, 102, 97, 108, 115, 101, 37, 50,
                            67, 37, 50, 50, 114, 119, 101, 98, 95, 116, 105, 112, 106, 97, 114, 95,
                            99, 111, 110, 115, 117, 109, 112, 116, 105, 111, 110, 95, 101, 110, 97,
                            98, 108, 101, 100, 37, 50, 50, 37, 51, 65, 116, 114, 117, 101, 37, 50,
                            67, 37, 50, 50, 114, 101, 115, 112, 111, 110, 115, 105, 118, 101, 95,
                            119, 101, 98, 95, 103, 114, 97, 112, 104, 113, 108, 95, 101, 120, 99,
                            108, 117, 100, 101, 95, 100, 105, 114, 101, 99, 116, 105, 118, 101, 95,
                            101, 110, 97, 98, 108, 101, 100, 37, 50, 50, 37, 51, 65, 116, 114, 117,
                            101, 37, 50, 67, 37, 50, 50, 118, 101, 114, 105, 102, 105, 101, 100,
                            95, 112, 104, 111, 110, 101, 95, 108, 97, 98, 101, 108, 95, 101, 110,
                            97, 98, 108, 101, 100, 37, 50, 50, 37, 51, 65, 102, 97, 108, 115, 101,
                            37, 50, 67, 37, 50, 50, 99, 114, 101, 97, 116, 111, 114, 95, 115, 117,
                            98, 115, 99, 114, 105, 112, 116, 105, 111, 110, 115, 95, 116, 119, 101,
                            101, 116, 95, 112, 114, 101, 118, 105, 101, 119, 95, 97, 112, 105, 95,
                            101, 110, 97, 98, 108, 101, 100, 37, 50, 50, 37, 51, 65, 116, 114, 117,
                            101, 37, 50, 67, 37, 50, 50, 114, 101, 115, 112, 111, 110, 115, 105,
                            118, 101, 95, 119, 101, 98, 95, 103, 114, 97, 112, 104, 113, 108, 95,
                            116, 105, 109, 101, 108, 105, 110, 101, 95, 110, 97, 118, 105, 103, 97,
                            116, 105, 111, 110, 95, 101, 110, 97, 98, 108, 101, 100, 37, 50, 50,
                            37, 51, 65, 116, 114, 117, 101, 37, 50, 67, 37, 50, 50, 114, 101, 115,
                            112, 111, 110, 115, 105, 118, 101, 95, 119, 101, 98, 95, 103, 114, 97,
                            112, 104, 113, 108, 95, 115, 107, 105, 112, 95, 117, 115, 101, 114, 95,
                            112, 114, 111, 102, 105, 108, 101, 95, 105, 109, 97, 103, 101, 95, 101,
                            120, 116, 101, 110, 115, 105, 111, 110, 115, 95, 101, 110, 97, 98, 108,
                            101, 100, 37, 50, 50, 37, 51, 65, 102, 97, 108, 115, 101, 37, 50, 67,
                            37, 50, 50, 99, 111, 109, 109, 117, 110, 105, 116, 105, 101, 115, 95,
                            119, 101, 98, 95, 101, 110, 97, 98, 108, 101, 95, 116, 119, 101, 101,
                            116, 95, 99, 111, 109, 109, 117, 110, 105, 116, 121, 95, 114, 101, 115,
                            117, 108, 116, 115, 95, 102, 101, 116, 99, 104, 37, 50, 50, 37, 51, 65,
                            116, 114, 117, 101, 37, 50, 67, 37, 50, 50, 99, 57, 115, 95, 116, 119,
                            101, 101, 116, 95, 97, 110, 97, 116, 111, 109, 121, 95, 109, 111, 100,
                            101, 114, 97, 116, 111, 114, 95, 98, 97, 100, 103, 101, 95, 101, 110,
                            97, 98, 108, 101, 100, 37, 50, 50, 37, 51, 65, 116, 114, 117, 101, 37,
                            50, 67, 37, 50, 50, 97, 114, 116, 105, 99, 108, 101, 115, 95, 112, 114,
                            101, 118, 105, 101, 119, 95, 101, 110, 97, 98, 108, 101, 100, 37, 50,
                            50, 37, 51, 65, 116, 114, 117, 101, 37, 50, 67, 37, 50, 50, 114, 101,
                            115, 112, 111, 110, 115, 105, 118, 101, 95, 119, 101, 98, 95, 101, 100,
                            105, 116, 95, 116, 119, 101, 101, 116, 95, 97, 112, 105, 95, 101, 110,
                            97, 98, 108, 101, 100, 37, 50, 50, 37, 51, 65, 116, 114, 117, 101, 37,
                            50, 67, 37, 50, 50, 103, 114, 97, 112, 104, 113, 108, 95, 105, 115, 95,
                            116, 114, 97, 110, 115, 108, 97, 116, 97, 98, 108, 101, 95, 114, 119,
                            101, 98, 95, 116, 119, 101, 101, 116, 95, 105, 115, 95, 116, 114, 97,
                            110, 115, 108, 97, 116, 97, 98, 108, 101, 95, 101, 110, 97, 98, 108,
                            101, 100, 37, 50, 50, 37, 51, 65, 116, 114, 117, 101, 37, 50, 67, 37,
                            50, 50, 118, 105, 101, 119, 95, 99, 111, 117, 110, 116, 115, 95, 101,
                            118, 101, 114, 121, 119, 104, 101, 114, 101, 95, 97, 112, 105, 95, 101,
                            110, 97, 98, 108, 101, 100, 37, 50, 50, 37, 51, 65, 116, 114, 117, 101,
                            37, 50, 67, 37, 50, 50, 108, 111, 110, 103, 102, 111, 114, 109, 95,
                            110, 111, 116, 101, 116, 119, 101, 101, 116, 115, 95, 99, 111, 110,
                            115, 117, 109, 112, 116, 105, 111, 110, 95, 101, 110, 97, 98, 108, 101,
                            100, 37, 50, 50, 37, 51, 65, 116, 114, 117, 101, 37, 50, 67, 37, 50,
                            50, 114, 101, 115, 112, 111, 110, 115, 105, 118, 101, 95, 119, 101, 98,
                            95, 116, 119, 105, 116, 116, 101, 114, 95, 97, 114, 116, 105, 99, 108,
                            101, 95, 116, 119, 101, 101, 116, 95, 99, 111, 110, 115, 117, 109, 112,
                            116, 105, 111, 110, 95, 101, 110, 97, 98, 108, 101, 100, 37, 50, 50,
                            37, 51, 65, 116, 114, 117, 101, 37, 50, 67, 37, 50, 50, 116, 119, 101,
                            101, 116, 95, 97, 119, 97, 114, 100, 115, 95, 119, 101, 98, 95, 116,
                            105, 112, 112, 105, 110, 103, 95, 101, 110, 97, 98, 108, 101, 100, 37,
                            50, 50, 37, 51, 65, 102, 97, 108, 115, 101, 37, 50, 67, 37, 50, 50, 99,
                            114, 101, 97, 116, 111, 114, 95, 115, 117, 98, 115, 99, 114, 105, 112,
                            116, 105, 111, 110, 115, 95, 113, 117, 111, 116, 101, 95, 116, 119,
                            101, 101, 116, 95, 112, 114, 101, 118, 105, 101, 119, 95, 101, 110, 97,
                            98, 108, 101, 100, 37, 50, 50, 37, 51, 65, 102, 97, 108, 115, 101, 37,
                            50, 67, 37, 50, 50, 102, 114, 101, 101, 100, 111, 109, 95, 111, 102,
                            95, 115, 112, 101, 101, 99, 104, 95, 110, 111, 116, 95, 114, 101, 97,
                            99, 104, 95, 102, 101, 116, 99, 104, 95, 101, 110, 97, 98, 108, 101,
                            100, 37, 50, 50, 37, 51, 65, 116, 114, 117, 101, 37, 50, 67, 37, 50,
                            50, 115, 116, 97, 110, 100, 97, 114, 100, 105, 122, 101, 100, 95, 110,
                            117, 100, 103, 101, 115, 95, 109, 105, 115, 105, 110, 102, 111, 37, 50,
                            50, 37, 51, 65, 116, 114, 117, 101, 37, 50, 67, 37, 50, 50, 116, 119,
                            101, 101, 116, 95, 119, 105, 116, 104, 95, 118, 105, 115, 105, 98, 105,
                            108, 105, 116, 121, 95, 114, 101, 115, 117, 108, 116, 115, 95, 112,
                            114, 101, 102, 101, 114, 95, 103, 113, 108, 95, 108, 105, 109, 105,
                            116, 101, 100, 95, 97, 99, 116, 105, 111, 110, 115, 95, 112, 111, 108,
                            105, 99, 121, 95, 101, 110, 97, 98, 108, 101, 100, 37, 50, 50, 37, 51,
                            65, 116, 114, 117, 101, 37, 50, 67, 37, 50, 50, 114, 119, 101, 98, 95,
                            118, 105, 100, 101, 111, 95, 116, 105, 109, 101, 115, 116, 97, 109,
                            112, 115, 95, 101, 110, 97, 98, 108, 101, 100, 37, 50, 50, 37, 51, 65,
                            116, 114, 117, 101, 37, 50, 67, 37, 50, 50, 108, 111, 110, 103, 102,
                            111, 114, 109, 95, 110, 111, 116, 101, 116, 119, 101, 101, 116, 115,
                            95, 114, 105, 99, 104, 95, 116, 101, 120, 116, 95, 114, 101, 97, 100,
                            95, 101, 110, 97, 98, 108, 101, 100, 37, 50, 50, 37, 51, 65, 116, 114,
                            117, 101, 37, 50, 67, 37, 50, 50, 108, 111, 110, 103, 102, 111, 114,
                            109, 95, 110, 111, 116, 101, 116, 119, 101, 101, 116, 115, 95, 105,
                            110, 108, 105, 110, 101, 95, 109, 101, 100, 105, 97, 95, 101, 110, 97,
                            98, 108, 101, 100, 37, 50, 50, 37, 51, 65, 116, 114, 117, 101, 37, 50,
                            67, 37, 50, 50, 114, 101, 115, 112, 111, 110, 115, 105, 118, 101, 95,
                            119, 101, 98, 95, 101, 110, 104, 97, 110, 99, 101, 95, 99, 97, 114,
                            100, 115, 95, 101, 110, 97, 98, 108, 101, 100, 37, 50, 50, 37, 51, 65,
                            102, 97, 108, 115, 101, 37, 55, 68, 14, 85, 82, 76, 95, 80, 65, 82, 65,
                            77, 83, 95, 71, 82, 68, 159, 37, 55, 66, 37, 50, 50, 119, 105, 116,
                            104, 65, 114, 116, 105, 99, 108, 101, 82, 105, 99, 104, 67, 111, 110,
                            116, 101, 110, 116, 83, 116, 97, 116, 101, 37, 50, 50, 37, 51, 65, 116,
                            114, 117, 101, 37, 50, 67, 37, 50, 50, 119, 105, 116, 104, 65, 114,
                            116, 105, 99, 108, 101, 80, 108, 97, 105, 110, 84, 101, 120, 116, 37,
                            50, 50, 37, 51, 65, 102, 97, 108, 115, 101, 37, 50, 67, 37, 50, 50,
                            119, 105, 116, 104, 71, 114, 111, 107, 65, 110, 97, 108, 121, 122, 101,
                            37, 50, 50, 37, 51, 65, 102, 97, 108, 115, 101, 37, 50, 67, 37, 50, 50,
                            119, 105, 116, 104, 68, 105, 115, 97, 108, 108, 111, 119, 101, 100, 82,
                            101, 112, 108, 121, 67, 111, 110, 116, 114, 111, 108, 115, 37, 50, 50,
                            37, 51, 65, 102, 97, 108, 115, 101, 37, 55, 68, 10, 99, 114, 101, 97,
                            116, 101, 100, 95, 97, 116, 30, 84, 104, 117, 32, 74, 117, 110, 32, 48,
                            54, 32, 50, 48, 58, 49, 50, 58, 50, 57, 32, 43, 48, 48, 48, 48, 32, 50,
                            48, 50, 52, 9, 102, 117, 108, 108, 95, 116, 101, 120, 116, 251, 32, 1,
                            66, 114, 101, 97, 107, 105, 110, 103, 32, 100, 111, 119, 110, 32, 116,
                            104, 101, 32, 115, 117, 109, 45, 99, 104, 101, 99, 107, 32, 112, 114,
                            111, 116, 111, 99, 111, 108, 92, 110, 92, 110, 70, 101, 119, 32, 109,
                            111, 110, 116, 104, 115, 32, 97, 103, 111, 32, 73, 32, 100, 105, 100,
                            32, 116, 104, 105, 115, 32, 105, 109, 112, 108, 101, 109, 101, 110,
                            116, 97, 116, 105, 111, 110, 32, 111, 102, 32, 116, 104, 101, 32, 115,
                            117, 109, 45, 99, 104, 101, 99, 107, 32, 112, 114, 111, 116, 111, 99,
                            111, 108, 32, 105, 110, 32, 82, 117, 115, 116, 44, 32, 97, 110, 100,
                            32, 119, 97, 110, 116, 101, 100, 32, 116, 111, 32, 109, 97, 107, 101,
                            32, 97, 110, 32, 97, 114, 116, 105, 99, 108, 101, 32, 97, 98, 111, 117,
                            116, 32, 105, 116, 33, 92, 110, 92, 110, 84, 111, 100, 97, 121, 32,
                            105, 115, 32, 116, 104, 101, 32, 100, 97, 121, 44, 32, 73, 32, 102,
                            105, 110, 97, 108, 108, 121, 32, 116, 111, 111, 107, 32, 116, 105, 109,
                            101, 32, 116, 111, 32, 119, 114, 105, 116, 101, 32, 97, 110, 32, 105,
                            110, 116, 114, 111, 100, 117, 99, 116, 105, 111, 110, 32, 116, 111, 32,
                            116, 104, 101, 32, 115, 117, 109, 45, 99, 104, 101, 99, 107, 32, 112,
                            114, 111, 116, 111, 99, 111, 108, 33, 32, 92, 117, 68, 56, 51, 69, 92,
                            117, 68, 69, 69, 49, 92, 110, 92, 110, 104, 116, 116, 112, 115, 58, 47,
                            47, 116, 46, 99, 111, 47, 72, 108, 117, 108, 55, 107, 87, 99, 67, 85,
                            11, 115, 99, 114, 101, 101, 110, 95, 110, 97, 109, 101, 10, 77, 97,
                            116, 116, 101, 111, 95, 77, 101, 114
                        ]
                        .to_vec(),
                        success: true,
                        program_outputs: [].to_vec()
                    }]
                );
            }
            Err(e) => panic!("Reclaim verification failed: {:?}", e),
        }
    }
}
