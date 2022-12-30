/*
https://cryptopals.com/sets/1/challenges/7

AES in ECB mode

The Base64-encoded content in this file has been encrypted via AES-128 in ECB
mode under the key

    "YELLOW SUBMARINE".

(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW
SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

Do this with code.

You can obviously decrypt this using the OpenSSL command-line tool, but we're
having you get ECB working in code for a reason. You'll need it a lot later on,
and not just for attacking ECB.
 */
use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit},
    Aes128,
};
use std::error::Error;

pub fn solve(ciphertext: &str) -> Result<String, Box<dyn Error>> {
    let key = GenericArray::from(b"YELLOW SUBMARINE".to_owned());
    let cipher = Aes128::new(&key);
    let bytes = base64::decode(ciphertext.trim().replace('\n', "").as_bytes())?;
    let plaintext: Vec<u8> = bytes
        .chunks(16)
        .flat_map(|chunk| {
            let bytes: [u8; 16] = chunk.try_into().unwrap();
            let mut block = GenericArray::from(bytes);
            cipher.decrypt_block(&mut block);
            block
        })
        .collect();

    Ok(String::from_utf8(plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_07() -> Result<(), Box<dyn Error>> {
        let input = include_str!("../data/7.txt");
        assert!(solve(input)?.contains("Supercalafragilisticexpialidocious"));
        Ok(())
    }
}
