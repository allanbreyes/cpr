use cpr::utils;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let valid: String = input
        .lines()
        .filter(|line| oracle(line.as_bytes().into()).is_ok())
        .collect();
    Some(valid)
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(15, false)?;
    cpr::solve!(15, solve, input).ok_or("no solution")?;
    Ok(())
}

fn oracle(pt: Vec<u8>) -> Result<(), Box<dyn Error>> {
    match utils::pkcs7_valid(&pt, 16) {
        true => Ok(()),
        false => Err("invalid padding".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(15, false)?;
        let want = Some("ICE ICE BABY\x04\x04\x04\x04".to_string());
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
