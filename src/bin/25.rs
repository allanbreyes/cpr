// Break "random access read/write" AES CTR
use cpr::utils;
use rand::Rng;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let pt = base64::decode(input).ok()?;
    let key = utils::rand_bytes(16);
    let nonce = rand::thread_rng().gen::<u64>();
    let ct = encrypt(&pt, &key, nonce);

    let oracle =
        |ct: &[u8], offset: usize, nt: &[u8]| -> Vec<u8> { edit(ct, &key, nonce, offset, nt) };

    let rec = attack(&ct, &oracle);

    // This is the same data from challenge 7, so let's just decrypt it
    Some(utils::utf8_decode(&utils::ecb(
        &rec,
        b"YELLOW SUBMARINE",
        utils::Op::Decrypt,
    )))
}

#[allow(clippy::type_complexity)] // ¯\_(ツ)_/¯ It's not that bad... maybe
fn attack(ct: &[u8], oracle: &dyn Fn(&[u8], usize, &[u8]) -> Vec<u8>) -> Vec<u8> {
    // If we "edit" the whole plaintext with zeroed out plaintext bytes, the
    // oracle spits out the keystream
    let keystream = oracle(ct, 0, &vec![0; ct.len()]);

    // With the keystream, we just need to XOR it with the ciphertext to get the
    // original plaintext
    utils::xor(ct, &keystream)
}

fn edit(ct: &[u8], key: &[u8], nonce: u64, offset: usize, nt: &[u8]) -> Vec<u8> {
    let mut pt = utils::ctr(ct, key, nonce);
    for (i, byte) in nt.iter().enumerate() {
        pt[offset + i] = *byte;
    }
    utils::ctr(&pt, key, nonce)
}

fn encrypt(pt: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    utils::ctr(pt, key, nonce)
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(25, true)?;
    cpr::solve!(25, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(25, true)?;
        let has = "I'm back and I'm ringin' the bell";
        let got = solve(input);
        assert!(got.unwrap().contains(has));
        Ok(())
    }
}
