/*
https://www.cryptopals.com/sets/1/challenges/2

Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965

... should produce:

746865206b696420646f6e277420706c6179
*/
use hex;

pub fn xor(h1: &str, h2: &str) -> String {
    let b1 = hex::decode(h1).unwrap();
    let b2 = hex::decode(h2).unwrap();
    let res = b1
        .iter()
        .zip(b2.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();
    hex::encode(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c02() {
        assert_eq!(
            xor(
                "1c0111001f010100061a024b53535009181c",
                "686974207468652062756c6c277320657965"
            ),
            "746865206b696420646f6e277420706c6179"
        );
    }
}
