// Implement CTR, the stream cipher mode
use cpr::utils;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let key = b"YELLOW SUBMARINE";
    let ct = base64::decode(input).ok()?;
    let pt = utils::ctr(&ct, key, 0);
    String::from_utf8(pt).ok()
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(18, true)?;
    cpr::solve!(18, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(18, true)?;
        let want = Some("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".into());
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
