use std::collections::VecDeque;

use anyhow::Error;
use hyle_contract_sdk::{BlobIndex, HyleOutput, StateDigest, TxHash};

pub fn parse_noir_output(vector: &mut Vec<String>) -> Result<HyleOutput, Error> {
    let version = u32::from_str_radix(vector.remove(0).strip_prefix("0x").unwrap(), 16)?;
    let initial_state = parse_array(vector)?;
    let next_state = parse_array(vector)?;
    let identity = parse_string(vector)?;
    let tx_hash = parse_string(vector)?;
    let index = u32::from_str_radix(vector.remove(0).strip_prefix("0x").unwrap(), 16)?;
    let blobs = parse_blobs(vector)?;
    let success = u32::from_str_radix(vector.remove(0).strip_prefix("0x").unwrap(), 16)? == 1;

    Ok(HyleOutput {
        version,
        initial_state: StateDigest(initial_state),
        next_state: StateDigest(next_state),
        identity: identity.into(),
        tx_hash: TxHash(tx_hash),
        index: BlobIndex(index as usize),
        blobs,
        success,
        program_outputs: vec![],
    })
}

fn parse_string(vector: &mut Vec<String>) -> Result<String, Error> {
    let length = usize::from_str_radix(vector.remove(0).strip_prefix("0x").unwrap(), 16)?;
    let mut resp = String::with_capacity(length);
    for _ in 0..length {
        let code = u32::from_str_radix(vector.remove(0).strip_prefix("0x").unwrap(), 16)?;
        let ch = std::char::from_u32(code)
            .ok_or_else(|| anyhow::anyhow!("Invalid char code: {}", code))?;
        resp.push(ch);
    }
    Ok(resp)
}

fn parse_array(vector: &mut Vec<String>) -> Result<Vec<u8>, Error> {
    let length = usize::from_str_radix(vector.remove(0).strip_prefix("0x").unwrap(), 16)?;
    let mut resp = Vec::with_capacity(length);
    for _ in 0..length {
        let num = u8::from_str_radix(vector.remove(0).strip_prefix("0x").unwrap(), 16)?;
        resp.push(num);
    }
    Ok(resp)
}

fn parse_blobs(vector: &mut Vec<String>) -> Result<Vec<u8>, Error> {
    let _blob_len = usize::from_str_radix(vector.remove(0).strip_prefix("0x").unwrap(), 16)?;
    // Arbitrary value that says that blobs field is size for only 10 elements
    let blob_data: Vec<String> = vector.drain(0..10.min(vector.len())).collect();
    let mut blob_data = VecDeque::from(blob_data);

    let blob_number = usize::from_str_radix(
        blob_data
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("Missing blob number"))?
            .strip_prefix("0x")
            .unwrap(),
        16,
    )?;
    let mut blobs = Vec::new();

    for _ in 0..blob_number {
        let blob_size = usize::from_str_radix(
            blob_data
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("Missing blob size"))?
                .strip_prefix("0x")
                .unwrap(),
            16,
        )?;

        for _ in 0..blob_size {
            let v = &blob_data
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("Missing blob data"))?;
            blobs.push(u8::from_str_radix(v.strip_prefix("0x").unwrap(), 16)?);
        }
    }

    Ok(blobs)
}