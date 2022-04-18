pub struct Candidate<T> {
    pub score: f32,
    pub value: T,
}

/// Compute the Hamming distance between two byte sequences..
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

/// Scores plaintext according to character frequency.
///
/// # Examples
/// ```
/// use cpr::utils::score_text;
/// assert!(score_text(b"Hello World!") > score_text(b"............"));
/// ```
pub fn score_text(text: &[u8]) -> f32 {
    let mut count = 0;
    for b in text.iter() {
        let c = *b as char;
        match c as char {
            'a'..='z' | 'A'..='Z' | ' ' => count += 1,
            _ => (),
        }
    }
    count as f32 / text.len() as f32
}

/// Apply a single byte XOR cipher to plaintext..
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
