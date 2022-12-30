// Single-byte XOR cipher
use cpr::utils;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let bytes = hex::decode(input).ok()?;
    let (_key, cracked) = utils::crack_single_byte_xor(&bytes, utils::score_text);
    String::from_utf8(cracked.value).ok()
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(3, true)?;
    cpr::solve!(3, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(3, true)?;
        let want = Some("Cooking MC's like a pound of bacon".into());
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
