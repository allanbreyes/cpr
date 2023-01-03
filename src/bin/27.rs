// Recover the key from CBC with IV=Key
use cpr::utils;
use rand::Rng;
use std::error::Error;

pub fn solve(_input: &str) -> Option<String> {
    let oracles = make_oracles();
    let key = attack(oracles)?;
    Some(hex::encode(&key))
}

fn attack(
    oracles: (
        impl Fn(Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>,
        impl Fn(Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>,
    ),
) -> Option<Vec<u8>> {
    let block_size = 16;
    let (encrypt, decrypt) = oracles;

    let mut rng = rand::thread_rng();

    // Keep trying to generate ciphertext that produces valid plaintext
    loop {
        let pt = (0..3 * block_size).map(|_| rng.gen_range(0..128)).collect();
        let ct = encrypt(pt).ok()?;

        // The calculation is straightforward and provided directly in the
        // prompt. We send a C1-00-C1 ciphertext to the oracle, and then XOR the
        // P1 and P3 block to back out the key.
        let c1 = ct[..block_size].to_vec();
        let cz = vec![0u8; block_size];

        if let Ok(pt) = decrypt([c1.clone(), cz, c1].concat()) {
            let key = utils::xor(&pt[..block_size], &pt[block_size * 2..block_size * 3]);
            return Some(key);
        }
    }
}

fn decrypt(ct: Vec<u8>, key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let pt = utils::cbc(&ct, key, key, utils::Op::Decrypt);
    // We're supposed to validate the plaintext on the output, but the problem
    // statement allows for returning the plaintext even if it's invalid. We can
    // just keep generating new ciphertexts until we get one the produces a
    // valid plaintext, or... let's just comment this out and assume that we can
    // pluck out the plaintext from the hypothetical error message.
    // validate(&pt)?;
    Ok(pt)
}

fn encrypt(pt: Vec<u8>, key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    validate(&pt)?;
    Ok(utils::cbc(&pt, key, key, utils::Op::Encrypt))
}

fn validate(pt: &[u8]) -> Result<(), Box<dyn Error>> {
    // "Verify each byte of the plaintext for ASCII compliance (ie, look for
    // high-ASCII values). Noncompliant messages should raise an exception or
    // return an error that includes the decrypted plaintext (this happens all
    // the time in real systems, for what it's worth).
    for byte in pt {
        if *byte > 127 {
            return Err("invalid bytes".into());
        }
    }
    Ok(())
}

fn make_oracles() -> (
    impl Fn(Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>,
    impl Fn(Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>,
) {
    let ke = utils::rand_bytes(16);
    let kd = ke.clone();
    let encrypt = move |pt: Vec<u8>| encrypt(pt.to_vec(), &ke[..]);
    let decrypt = move |ct: Vec<u8>| decrypt(ct.to_vec(), &kd[..]);
    (encrypt, decrypt)
}

fn main() -> Result<(), Box<dyn Error>> {
    cpr::solve!(27, solve, "").ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let got = solve("");
        assert!(got.is_some());
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt() -> Result<(), Box<dyn Error>> {
        let key = b"YELLOW SUBMARINE";
        let pt1 = b"GREEN LOCOMOTIVE";
        let ct = encrypt(pt1.to_vec(), key)?;
        let pt2 = decrypt(ct, key)?;
        let s2 = String::from_utf8(pt2.to_vec())?;
        assert!(s2.contains("GREEN LOCOMOTIVE"));
        Ok(())
    }
}
