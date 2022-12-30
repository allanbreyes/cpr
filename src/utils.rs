pub struct Candidate<T> {
    pub score: f32,
    pub value: T,
}

/// Crack a single-byte XOR cipher.
///
/// See challenge 3.
pub fn crack_single_byte_xor(
    ciphertext: &[u8],
    heuristic: fn(bytes: &[u8]) -> f32,
) -> (u8, Vec<u8>) {
    let mut best = Candidate {
        score: 0.,
        value: Vec::new(),
    };
    let mut best_key = 0;
    for key in 0..=255 {
        let value = single_byte_xor(ciphertext, key);
        let score = heuristic(&value);
        if score > best.score {
            best = Candidate { score, value };
            best_key = key;
        }
    }
    (best_key, best.value)
}

/// Compute the Hamming distance between two byte sequences.
///
/// # Examples
/// ```
/// use cpr::utils::hamming;
/// assert_eq!(hamming(b"this is a test", b"wokka wokka!!!"), 37);
/// assert_eq!(hamming(b"foo", b"foo"), 0);
/// ```
pub fn hamming(s1: &[u8], s2: &[u8]) -> u32 {
    s1.iter()
        .zip(s2.iter())
        .map(|(c1, c2)| (c1 ^ c2).count_ones())
        .sum()
}

/// PKCS#7 padding.
///
/// See challenge 9.
pub fn pkcs7_pad(bytes: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (bytes.len() % block_size);
    let mut padded = bytes.to_vec();
    padded.append(&mut vec![pad_len as u8; pad_len]);
    padded
}

/// Apply a repeating-key XOR.
///
/// See chalenge 5.
pub fn repeating_key_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect()
}

/// Scores plaintext according to English character frequency.
///
/// # Examples
/// ```
/// use cpr::utils::score_text;
/// assert!(score_text(b"Hello World!") > score_text(b"............"));
/// ```
pub fn score_text(text: &[u8]) -> f32 {
    text.iter()
        .map(|b| {
            let c = *b as char;
            let adder: f32 = if c.is_ascii_lowercase() { 1. } else { 0. };
            adder
                + match c.to_ascii_lowercase() {
                    'a' => 8.2,
                    'b' => 1.5,
                    'c' => 2.8,
                    'd' => 4.3,
                    'e' => 13.,
                    'f' => 2.2,
                    'g' => 2.,
                    'h' => 6.1,
                    'i' => 7.,
                    'j' => 0.15,
                    'k' => 0.77,
                    'l' => 4.,
                    'm' => 2.4,
                    'n' => 6.7,
                    'o' => 7.5,
                    'p' => 1.9,
                    'q' => 0.095,
                    'r' => 6.,
                    's' => 6.3,
                    't' => 9.1,
                    'u' => 2.8,
                    'v' => 0.98,
                    'w' => 2.4,
                    'x' => 0.15,
                    'y' => 2.,
                    'z' => 0.074,
                    ' ' => 3.,
                    '0'..='9' => 1.,
                    _ => 0.,
                }
        })
        .sum::<f32>()
        / text.len() as f32
}

/// Apply a single byte XOR cipher to plaintext.
///
/// # Examples
/// ```
/// use cpr::utils::single_byte_xor;
/// assert_eq!(single_byte_xor(b"foo", 0x00), b"foo");
/// assert_eq!(single_byte_xor(b"foo", 0x01), b"gnn");
/// ```
pub fn single_byte_xor(plaintext: &[u8], key: u8) -> Vec<u8> {
    plaintext.iter().map(|b| b ^ key).collect()
}
