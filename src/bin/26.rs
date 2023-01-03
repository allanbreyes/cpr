// CTR bitflipping
use cpr::utils;
use rand::Rng;
use std::error::Error;

pub fn solve(_input: &str) -> Option<String> {
    let (encrypt, decrypt) = make_oracles();
    let block_size = 16;

    let goal = b";admin=true".to_vec();

    // Encrypt a dummy plaintext to get a ciphertext that we can work with. This
    // is extremely similar to challenge 16's bit-flipping attack.
    let pt1 = b"A".repeat(goal.len());
    let ct1 = encrypt(pt1.clone());

    // Generate an XOR string that we can apply to the ciphertext to flip the
    // necessary bits that when XOR'ed with the keystream, will give us our goal
    let xor = [
        vec![0; block_size * 2],
        utils::xor(&goal, &pt1),
        vec![0; 42],
    ]
    .concat();
    let ct2 = utils::xor(&ct1, &xor);

    // Lastly, decrypt the tampered ciphertext and check if we got our goal
    let pt2 = decrypt(ct2);
    Some(utils::utf8_decode(&pt2))
}

fn decrypt(ct: Vec<u8>, key: &[u8], nonce: u64) -> Vec<u8> {
    utils::ctr(&ct, key, nonce)
}

fn encrypt(pt: Vec<u8>, key: &[u8], nonce: u64) -> Vec<u8> {
    // Mostly copied straight from challenge 16. It's not worth DRYing out.
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

    utils::ctr(&full, key, nonce)
}

fn make_oracles() -> (impl Fn(Vec<u8>) -> Vec<u8>, impl Fn(Vec<u8>) -> Vec<u8>) {
    let ke = utils::rand_bytes(16);
    let kd = ke.clone();
    let ne = rand::thread_rng().gen();
    let nd = ne;
    let encrypt = move |pt: Vec<u8>| encrypt(pt.to_vec(), &ke[..], ne);
    let decrypt = move |ct: Vec<u8>| decrypt(ct.to_vec(), &kd[..], nd);
    (encrypt, decrypt)
}

fn main() -> Result<(), Box<dyn Error>> {
    cpr::solve!(26, solve, "").ok_or("no solution")?;
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
        let nonce = 0;
        let pt1 = b";admin=true";
        let ct = encrypt(pt1.to_vec(), key, nonce);
        let pt2 = decrypt(ct, key, nonce);
        let s2 = String::from_utf8(pt2.to_vec())?;
        assert!(s2.contains("%3Badmin%3Dtrue"));
        Ok(())
    }
}
