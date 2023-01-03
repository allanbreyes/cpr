// CBC bitflipping attacks
use cpr::utils;
use std::error::Error;

pub fn solve(_input: &str) -> Option<String> {
    let (encrypt, decrypt) = make_oracles();

    let (_, block_size) = utils::detect_lengths(&encrypt, 100)?;

    // .. | 0123456789abcdef | 0123456789abcdef | 0123456789abcdef | ..
    // iv | comment1=cooking | %20MCs;userdata= | AAAAAAAAAAAAAAAA | ..
    //                         ^corrupt           ^target
    let goal = b";admin=true".to_vec();

    let pt1 = b"A".repeat(goal.len());
    let mut ct = encrypt(pt1).ok()?;

    for (i, b) in goal.iter().enumerate() {
        let j = i + block_size * 2;
        ct[j] ^= b'A' ^ b;
    }

    let pt2 = decrypt(ct).ok()?;
    Some(utils::utf8_decode(&pt2).trim().to_string())
}

fn decrypt(ct: Vec<u8>, key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let iv = ct[..key.len()].to_vec();
    let pt = utils::cbc(&ct[key.len()..], key, &iv, utils::Op::Decrypt);
    Ok(pt)
}

fn encrypt(pt: Vec<u8>, key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let iv = utils::rand_bytes(key.len());
    let sanitized = pt
        .iter()
        .flat_map(|&c| match c {
            b';' => b"%3B".to_vec(),
            b'=' => b"%3D".to_vec(),
            b' ' => b"%20".to_vec(),
            _ => [c].to_vec(),
        })
        .collect::<Vec<u8>>();
    let full = [
        b"comment1=cooking%20MCs;userdata=".to_vec(),
        sanitized,
        b";comment2=%20like%20a%20pound%20of%20bacon".to_vec(),
    ]
    .concat();

    Ok([iv.clone(), utils::cbc(&full, key, &iv, utils::Op::Encrypt)].concat())
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
    cpr::solve!(16, solve, "").ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let has = ";admin=true";
        let got = solve("");
        assert!(got.unwrap().contains(has));
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt() -> Result<(), Box<dyn Error>> {
        let key = b"YELLOW SUBMARINE";
        let pt1 = b";admin=true";
        let ct = encrypt(pt1.to_vec(), key)?;
        let pt2 = decrypt(ct, key)?;
        let s2 = String::from_utf8(pt2.to_vec())?;
        assert!(s2.contains("%3Badmin%3Dtrue"));
        Ok(())
    }
}
