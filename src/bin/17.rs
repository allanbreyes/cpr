// The CBC padding oracle
use cpr::utils;
use rand::seq::SliceRandom;
use std::{collections::HashSet, error::Error};

pub fn solve(input: &str) -> Option<String> {
    let (get, validate) = make_oracles(input);
    let mut pts = HashSet::new();

    // Keep cracking messages until we have 10 unique messages
    while pts.len() < 10 {
        let pt = attack(get(), &validate).ok()?;
        pts.insert(pt.clone());
    }

    // Collect and sort them
    let mut full: Vec<String> = pts
        .iter()
        .map(|pt| match utils::pkcs7_unpad(pt) {
            Some(unpadded) => utils::utf8_decode(&unpadded),
            None => utils::utf8_decode(pt),
        })
        .collect();
    full.sort();

    Some(full.join("\n"))
}

fn attack(cg: Vec<u8>, oracle: &impl Fn(Vec<u8>) -> bool) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut msg = vec![];
    let (mut iv, ct) = cg.split_at(16);

    // Attack block by block until we uncover the final block
    for block in ct.chunks(16) {
        let zeroing_iv = attack_block(block, oracle)?;
        let pt = utils::xor(iv, &zeroing_iv);
        msg.extend(pt);
        iv = block;
    }

    Ok(msg)
}

fn attack_block(
    block: &[u8],
    oracle: &impl Fn(Vec<u8>) -> bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut zeroing_iv = vec![0; block.len()];

    // Go from 1 to full padding to fill in the zeroing IV
    for pad in 1..=block.len() {
        let mut padding_iv = utils::xor(&zeroing_iv[..], &vec![pad as u8; block.len()]);

        let mut broken = false;
        let mut found: usize = 0;

        // Brute force until we find the correct byte that passes the oracle
        for candidate in 0..=255 {
            padding_iv[block.len() - pad] = candidate;
            if oracle([padding_iv.clone(), block.to_vec()].concat()) {
                if pad == 1 {
                    // Tamper with second to last byte to see if it's a real
                    // padding byte or not. This becomes increasingly less
                    // probably as the padding value increases.
                    padding_iv[block.len() - pad - 1] ^= 1;
                    if !oracle([padding_iv.clone(), block.to_vec()].concat()) {
                        continue;
                    }
                }

                // We found the correct byte! Break out and continue to next
                broken = true;
                found = candidate as usize;
                break;
            }
        }

        if !broken {
            return Err("failed to break block".into());
        }

        // XOR the found byte to get the correct value for the zeroing IV
        zeroing_iv[block.len() - pad] = (found as u8) ^ (pad as u8);
    }

    Ok(zeroing_iv)
}

fn decrypt(cg: Vec<u8>, key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let block_size = key.len();
    let (iv, ct) = cg.split_at(key.len());
    let pt = utils::cbc(ct, key, iv, block_size, true);
    Ok(pt)
}

fn encrypt(pt: Vec<u8>, key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let iv = utils::rand_bytes(key.len());
    let ct = utils::cbc(&pt, key, &iv, key.len(), false);
    Ok([iv, ct].concat())
}

fn make_oracles(input: &str) -> (impl Fn() -> Vec<u8>, impl Fn(Vec<u8>) -> bool) {
    let pts = input
        .lines()
        .map(|l| base64::decode(l).unwrap())
        .collect::<Vec<Vec<u8>>>();

    let ke = utils::rand_bytes(16);
    let kd = ke.clone();
    let get = move || {
        let pt = pts.choose(&mut rand::thread_rng()).unwrap();
        encrypt(pt.to_vec(), &ke[..]).unwrap()
    };
    let validate = move |cg: Vec<u8>| {
        let pt = decrypt(cg.to_vec(), &kd[..]).unwrap();
        utils::pkcs7_valid(&pt, kd.len())
    };
    (get, validate)
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(17, false)?;
    cpr::solve!(17, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(17, false)?;
        let has = "000000Now that the party is jumping";
        let got = solve(input);
        assert!(got.unwrap().contains(has));
        Ok(())
    }

    #[test]
    fn test_oracles() {
        let input = base64::encode("ICE ICE BABY".as_bytes());
        let (get, validate) = make_oracles(&input);
        let cg = get();
        assert!(validate(cg));
    }
}
