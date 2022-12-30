// Convert hex to base64
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let bytes = hex::decode(input).ok()?;
    Some(base64::encode(&bytes))
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(1, true)?;
    cpr::solve!(1, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(1, true)?;
        let want = Some("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".into());
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
