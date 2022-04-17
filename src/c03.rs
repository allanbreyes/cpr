/*
https://www.cryptopals.com/sets/1/challenges/3

Single-byte XOR cipher

The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency
is a good metric. Evaluate each output and choose the one with the best score.
*/
use hex;

struct Candidate {
    score: u32,
    text: String,
}

pub fn crack(hex: &str) -> String {
    let bytes = hex::decode(hex).unwrap();
    let mut candidate = Candidate {
        score: 0,
        text: String::new(),
    };
    for key in 0..255 {
        let text = decrypt(&bytes, key);
        let score = score_text(&text);
        if score > candidate.score {
            candidate = Candidate { score, text };
        }
    }
    candidate.text
}

fn decrypt(bytes: &[u8], key: u8) -> String {
    let mut decrypted = String::new();
    for byte in bytes {
        decrypted.push((byte ^ key.clone()) as char);
    }
    decrypted
}

fn score_text(text: &str) -> u32 {
    let mut score = 0;
    for c in text.chars() {
        match c {
            'a'..='z' => score += 1,
            'A'..='Z' => score += 1,
            _ => (),
        }
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c03() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let expected = "Cooking MC's like a pound of bacon";
        let actual = crack(input);
        assert_eq!(actual, expected);
    }
}
