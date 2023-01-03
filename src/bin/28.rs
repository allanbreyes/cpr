// Implement a SHA-1 keyed MAC
use sha1::{Digest, Sha1};
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let key = b"YELLOW SUBMARINE".to_vec();
    let msg = input.as_bytes().to_vec();

    let mut sha = Sha1::new();
    sha.update([key.clone(), msg.clone()].concat());
    let mac = sha.finalize();

    // Verify that you cannot tamper with the message without breaking the MAC
    // you've produced
    let mut sha = Sha1::new();
    sha.update([key, msg.clone(), b"tampered".to_vec()].concat());
    let tampered_mac = sha.finalize();
    assert_ne!(mac, tampered_mac);

    // ...and that you can't produce a new MAC without knowing the secret key.
    let mut sha = Sha1::new();
    sha.update([b"wrong key".to_vec(), msg].concat());
    let wrong_key_mac = sha.finalize();
    assert_ne!(mac, wrong_key_mac);

    Some(hex::encode(mac))
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(28, false)?;
    cpr::solve!(28, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(28, false)?;
        let want = Some("07479953c4ccec361322ceeaa70f6ddbb71e8387".into());
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
