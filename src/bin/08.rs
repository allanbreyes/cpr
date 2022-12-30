// Detect AES in ECB mode
use std::{collections::HashMap, error::Error};

pub fn solve(ciphertexts: &str) -> Option<String> {
    let (_, line) = ciphertexts
        .trim()
        .lines()
        .find_map(|line| {
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
                Some((score, line.to_string()))
            } else {
                None
            }
        })
        .unwrap();
    Some(line)
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(8, false)?;
    cpr::solve!(8, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(8, false)?;
        let has = "08649af70dc06f4fd5d2d69c744cd283";
        let got = solve(input).unwrap();
        assert!(got.contains(has));
        assert_eq!(got.len(), 320);
        Ok(())
    }
}
