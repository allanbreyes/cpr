/*
https://www.cryptopals.com/sets/1/challenges/5

Implement repeating-key XOR

Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext
will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your
password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
 */
use super::utils;

pub fn solve(plaintext: &str, key: &str) -> String {
    let ciphertext = utils::repeating_key_xor(plaintext.as_bytes(), key.as_bytes());
    hex::encode(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c05() {
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";
        let ciphertext = solve(plaintext, key);
        assert_eq!(
            ciphertext,
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }
}
