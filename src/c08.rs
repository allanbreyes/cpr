/*
https://cryptopals.com/sets/1/challenges/8

Detect AES in ECB mode

In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic;
the same 16 byte plaintext block will always produce the same 16 byte
ciphertext.
 */
use std::{collections::HashMap, error::Error};

pub fn solve(ciphertexts: &str) -> Result<String, Box<dyn Error>> {
    let (_, line) = ciphertexts
        .trim()
        .lines()
        .filter_map(|line| {
            let ciphertext = hex::decode(line).ok()?;
            let mut blocks = HashMap::new();
            for block in ciphertext.chunks(16) {
                *blocks.entry(block).or_insert(0) += 1;
            }
            let score: u32 = blocks
                .values()
                .filter_map(|&count| if count > 1 { Some(count) } else { None })
                .sum();
            if score > 0 {
                Some((score, line))
            } else {
                None
            }
        })
        .next()
        .ok_or("no candidate found")?;
    Ok(line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_08() -> Result<(), Box<dyn Error>> {
        let input = include_str!("../data/8.txt");
        assert!(solve(input)?.contains("08649af70dc06f4fd5d2d69c744cd283"));
        Ok(())
    }
}
