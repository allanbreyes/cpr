// Implement repeating-key XOR
use cpr::utils;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let key = b"ICE";
    let ciphertext = utils::repeating_key_xor(input.trim().as_bytes(), key);
    Some(hex::encode(ciphertext))
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(5, false)?;
    cpr::solve!(5, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(5, false)?;
        let want = Some("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".into());
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
