// Detect AES in ECB mode
use cpr::utils;
use std::error::Error;

pub fn solve(ciphertexts: &str) -> Option<String> {
    let line = ciphertexts
        .trim()
        .lines()
        .find_map(|line| {
            let ciphertext = hex::decode(line).ok()?;
            if utils::detect_ecb(&ciphertext, 16) {
                Some(line.to_string())
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
