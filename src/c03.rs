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
use super::utils;
use hex;

pub fn solve(hex: &str) -> Option<String> {
    let bytes = hex::decode(hex).unwrap();
    let mut candidate = utils::Candidate {
        score: 0.,
        value: Vec::new(),
    };
    for key in 0..=255 {
        let xored = utils::single_byte_xor(&bytes, key);
        let score = utils::score_text(&xored);
        if score > candidate.score {
            candidate = utils::Candidate {
                score,
                value: xored,
            };
        }
    }
    let result = String::from_utf8(candidate.value);
    match result {
        Ok(result) => Some(result),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c03() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let expected = "Cooking MC's like a pound of bacon";
        let actual = solve(input).unwrap();
        assert_eq!(actual, expected);
    }
}
