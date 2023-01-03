// Implement CBC mode
use cpr::utils;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let key: &[u8] = b"YELLOW SUBMARINE";
    let iv = [0; 16];
    let ciphertext = base64::decode(input.trim()).ok()?;
    let plaintext = utils::cbc(&ciphertext, key, &iv, utils::Op::Decrypt);
    String::from_utf8(plaintext).ok()
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(10, true)?;
    cpr::solve!(10, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(10, true)?;
        let has = "play that funky music";
        let got = solve(input);
        assert!(got.unwrap().contains(has));
        Ok(())
    }
}
