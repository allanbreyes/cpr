// AES in ECB mode
use aes::cipher::generic_array::GenericArray;
use cpr::utils;
use std::error::Error;

pub fn solve(ciphertext: &str) -> Option<String> {
    let key = GenericArray::from(b"YELLOW SUBMARINE".to_owned());
    let bytes = base64::decode(ciphertext.trim().replace('\n', "").as_bytes()).ok()?;
    let plaintext = utils::ecb(&bytes, &key, utils::Op::Decrypt);
    String::from_utf8(plaintext).ok()
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(7, false)?;
    cpr::solve!(7, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = cpr::read_data(7, false)?;
        let has = "Supercalafragilisticexpialidocious";
        let got = solve(&input).unwrap();
        assert!(got.contains(has));
        Ok(())
    }
}
