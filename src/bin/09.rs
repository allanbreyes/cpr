// Implement PKCS#7 padding
use cpr::utils;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let padded = utils::pkcs7_pad(bytes, 20);
    String::from_utf8(padded).ok()
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(9, false)?;
    cpr::solve!(9, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(9, true)?;
        let want = Some("YELLOW SUBMARINE\x04\x04\x04\x04".into());
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
