use cpr::utils;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let plaintext = base64::decode(input.trim()).ok()?;
    let oracle = make_oracle(plaintext);
    let decrypted = attack(&oracle)?;
    String::from_utf8(decrypted).ok()
}

fn attack(oracle: &utils::Oracle) -> Option<Vec<u8>> {
    // Detect length, block size, and usage of ECB mode
    let (length, block_size) = utils::detect_lengths(oracle, 128)?;
    if !utils::detect_ecb(&oracle(vec![0; block_size * 3]).ok()?, block_size) {
        eprintln!("didn't detect ECB");
        return None;
    }

    let mut decrypted = Vec::new();
    let size = ((length / block_size) + 1) * block_size;
    for i in (1..size).rev() {
        let query = vec![0x41; i];
        let target = oracle(query.clone()).ok()?[..size].to_vec();
        for j in 0..=255 {
            let mut prefix = query.to_owned();
            prefix.extend(&decrypted);
            prefix.push(j);
            let ciphertext = oracle(prefix.clone()).ok()?[..size].to_vec();
            if ciphertext == target {
                decrypted.push(j);
                break;
            }
        }
    }
    Some(decrypted[..length].to_vec())
}

fn make_oracle(plaintext: Vec<u8>) -> impl Fn(Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = utils::rand_bytes(16);
    move |prefix: Vec<u8>| {
        let ct = utils::ecb(
            &prefix
                .iter()
                .chain(plaintext.iter())
                .cloned()
                .collect::<Vec<u8>>(),
            &key,
            16,
            false,
        );
        Ok(ct)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(12, true)?;
    cpr::solve!(12, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(12, true)?;
        let want = Some("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n".into());
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
