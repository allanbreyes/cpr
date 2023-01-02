// Byte-at-a-time ECB decryption (Harder)
use cpr::utils;
use rand::Rng;
use std::{collections::HashMap, error::Error};

pub fn solve(input: &str) -> Option<String> {
    let target = base64::decode(input.trim()).ok()?;
    let oracle = make_oracle(target);
    let decrypted = attack(&oracle)?;
    String::from_utf8(decrypted).ok()
}

fn attack(oracle: &utils::Oracle) -> Option<Vec<u8>> {
    // Probe oracle
    let (length, block_size) = utils::detect_lengths(oracle, 100)?;
    if !utils::detect_ecb(&oracle(vec![0x41; block_size * 3]).ok()?, block_size) {
        eprintln!("didn't detect ECB");
        return None;
    }

    // Probe the prefix
    let prefix_length = find_prefix_length(oracle, block_size)?;
    let prefix_padding_length = block_size - (prefix_length % block_size);
    let prefix_padding = vec![0x41_u8; prefix_padding_length];

    // Uncover one byte at a time
    // prefix | prefix_padding | attack | target
    // 0123456789abcdef | 0123456789abcdef | 0123456789abcdef | 0123456789abcdef
    // PPPPPPPPAAAAAAAA | BBBBBBBBBBBBBBBB | BBBBBBBBBBBBBBBs | sssssssssssssss
    // ^prefix ^padding   ^attack                           ^target
    let mut decrypted = Vec::new();
    let top = ((length + prefix_padding_length) / block_size + 1) * block_size;
    let bot = prefix_length + prefix_padding_length;
    let size = top - bot;
    for i in (1..size).rev() {
        let mut query = prefix_padding.clone();
        query.extend(&vec![0x42; i]);
        let target = oracle(query.clone()).ok()?[bot..top].to_vec();

        for j in 0..=255 {
            let mut attacker = query.to_owned();
            attacker.extend(&decrypted);
            attacker.push(j);
            let ciphertext = oracle(attacker.clone()).ok()?[bot..top].to_vec();
            if ciphertext == target {
                decrypted.push(j);
                break;
            }
        }
    }

    Some(decrypted[..(length - prefix_length)].to_vec())
}

fn find_prefix_length(oracle: &utils::Oracle, block_size: usize) -> Option<usize> {
    // Force the oracle to show a repeated block
    let ct = oracle(vec![0x41; block_size * 3]).ok()?;
    let binding = ct
        .chunks(block_size)
        .enumerate()
        .fold(HashMap::new(), |mut acc, (i, chunk)| {
            acc.entry(chunk).or_insert(Vec::new()).push(i);
            acc
        });
    let (block_index, repeated_block) =
        binding
            .iter()
            .find_map(|(k, v)| if v.len() > 1 { Some((v[0], k)) } else { None })?;

    // Find the pad length needed to elicit the repeated block
    for i in 0..block_size * 2 {
        let ct = oracle(vec![0x41; i]).ok()?;
        if ct.chunks(block_size).any(|chunk| chunk == *repeated_block) {
            let j = i - block_size;
            return Some(block_index * block_size - j);
        }
    }
    None
}

fn make_oracle(target: Vec<u8>) -> impl Fn(Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = utils::rand_bytes(16);
    let prefix = utils::rand_bytes(rand::thread_rng().gen_range(4..32));

    move |pt: Vec<u8>| {
        let all = prefix
            .iter()
            .chain(pt.iter())
            .chain(target.iter())
            .cloned()
            .collect::<Vec<u8>>();
        Ok(utils::ecb(&all, &key, 16, false))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(14, true)?;
    cpr::solve!(14, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(14, true)?;
        let want = Some("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n".into());
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
