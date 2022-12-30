// Fixed XOR
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let (input, key) = parse(input)?;
    let res = input
        .iter()
        .zip(key.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();
    Some(hex::encode(res))
}

fn parse(input: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let (a, b) = input.trim().split_once('\n')?;
    Some((hex::decode(a).ok()?, hex::decode(b).ok()?))
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(2, false)?;
    cpr::solve!(2, solve, input);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(2, false)?;
        let want = Some("746865206b696420646f6e277420706c6179".into());
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
