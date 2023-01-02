use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use rand::Rng;
use std::collections::HashMap;

pub struct Candidate<T> {
    pub score: f32,
    pub value: T,
}

pub type Oracle = dyn Fn(Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

/// Apply AES in CBC mode.
///
/// See challenge 10.
///
/// # Examples
/// ```
/// use cpr::utils::{cbc, rand_bytes};
/// let key = rand_bytes(16);
/// let iv = rand_bytes(key.len());
/// let pt = b"YELLOW SUBMARINE";
/// let ct = cbc(pt, &key, &iv, key.len(), false);
/// let out = cbc(&ct, &key, &iv, key.len(), true);
/// assert_eq!(pt, &out[..]);
/// ```
pub fn cbc(bytes: &[u8], key: &[u8], iv: &[u8], block_size: usize, decrypt: bool) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut prev = iv.to_vec();
    pkcs7_pad(bytes, block_size)
        .chunks(block_size)
        .flat_map(|chunk| {
            if decrypt {
                let mut block = GenericArray::from_slice(chunk).to_owned();
                cipher.decrypt_block(&mut block);
                let out = block
                    .iter()
                    .zip(prev.iter())
                    .map(|(b, p)| b ^ p)
                    .collect::<Vec<u8>>();
                prev = chunk.to_owned();
                out
            } else {
                let xor = chunk
                    .iter()
                    .zip(prev.iter())
                    .map(|(b, p)| b ^ p)
                    .collect::<Vec<u8>>();
                let mut block = GenericArray::from_slice(&xor).to_owned();
                cipher.encrypt_block(&mut block);
                let out = block.to_vec();
                prev = out.to_owned();
                out
            }
        })
        .collect()
}

/// Crack a single-byte XOR cipher.
///
/// See challenge 3.
pub fn crack_single_byte_xor(
    ciphertext: &[u8],
    heuristic: fn(bytes: &[u8]) -> f32,
) -> (u8, Candidate<Vec<u8>>) {
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
    (best_key, best)
}

/// CTR stream cipher.
///
/// See challenge 18.
pub fn ctr(bytes: &[u8], key: &[u8], nonce: u64, block_size: usize) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut counter: u64 = 0;
    bytes
        .chunks(block_size)
        .flat_map(|chunk| {
            let mut block = GenericArray::from_slice(
                &nonce
                    .to_le_bytes()
                    .iter()
                    .chain(&counter.to_le_bytes())
                    .cloned()
                    .collect::<Vec<u8>>(),
            )
            .to_owned();
            cipher.encrypt_block(&mut block);
            let out = block
                .iter()
                .zip(chunk.iter())
                .map(|(b, p)| b ^ p)
                .collect::<Vec<u8>>();
            counter += 1;
            out
        })
        .collect()
}

/// Detect length and block size given an encryption oracle.
pub fn detect_lengths(oracle: &Oracle, max_guess: usize) -> Option<(usize, usize)> {
    let mut prev = oracle(b"".to_vec()).ok()?;
    let length = prev.len();
    for i in 0..max_guess {
        let out = oracle(vec![0x41; i]).ok()?;
        if out.len() > prev.len() {
            return Some((length - i + 1, out.len() - prev.len()));
        }
        prev = out;
    }
    None
}

/// Detect AES in ECB mode.
///
/// See challenge 8.
/// TODO: automatically try and detect block size?
pub fn detect_ecb(ciphertext: &[u8], block_size: usize) -> bool {
    ciphertext
        .chunks(block_size)
        .fold(HashMap::new(), |mut blocks, block| {
            *blocks.entry(block).or_insert(0) += 1;
            blocks
        })
        .values()
        .filter_map(|&count| if count > 1 { Some(count) } else { None })
        .sum::<u32>()
        > 0
}

/// Apply AES in ECB mode.
///
/// See challenge 7.
pub fn ecb(bytes: &[u8], key: &[u8], block_size: usize, decrypt: bool) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    pkcs7_pad(bytes, block_size)
        .chunks(block_size)
        .flat_map(|chunk| {
            let mut block = GenericArray::from_slice(chunk).to_owned();
            if decrypt {
                cipher.decrypt_block(&mut block);
            } else {
                cipher.encrypt_block(&mut block);
            }
            block.to_vec()
        })
        .collect()
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

/// MT19937 PRNG.
///
/// See challenge 21 or https://en.wikipedia.org/wiki/Mersenne_Twister
pub struct MT19937 {
    pub mt: Vec<u32>,
    pub index: usize,
    config: MT19937Config,
}

struct MT19937Config {
    // w: u32,
    n: usize,
    m: usize,
    // r: u32,
    a: u32,
    u: u32,
    d: u32,
    s: u32,
    b: u32,
    t: u32,
    c: u32,
    l: u32,
    lower_mask: u32,
    upper_mask: u32,
}

impl Default for MT19937 {
    fn default() -> Self {
        Self::new()
    }
}

impl MT19937 {
    pub fn new() -> Self {
        Self::from_seed(rand::thread_rng().gen())
    }

    pub fn from_seed(seed: u32) -> Self {
        // Use known coefficients
        let n = 624;
        let r = 31;
        let w = 32;
        let config = MT19937Config {
            n,
            m: 397,
            a: 0x9908B0DF,
            u: 11,
            d: 0xFFFFFFFF,
            s: 7,
            b: 0x9D2C5680,
            t: 15,
            c: 0xEFC60000,
            l: 18,
            lower_mask: (1 << r) - 1,
            upper_mask: !((1 << r) - 1),
        };

        // Initialization
        let mut mt = vec![0; n];
        let index = n;

        // Seed
        mt[0] = seed;
        for i in 1..n {
            mt[i] = 1812433253_u32
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> (w - 2)))
                .wrapping_add(i as u32);
        }

        Self { mt, index, config }
    }

    pub fn gen(&mut self) -> u32 {
        if self.index >= self.config.n {
            self.twist();
        }

        let mut y = self.mt[self.index];
        y ^= (y >> self.config.u) & self.config.d;
        y ^= (y << self.config.s) & self.config.b;
        y ^= (y << self.config.t) & self.config.c;
        y ^= y >> self.config.l;

        self.index += 1;
        y
    }

    fn twist(&mut self) {
        let config = &self.config;
        let n = config.n;
        let m = config.m;
        let a = config.a;
        let lower_mask = config.lower_mask;
        let upper_mask = config.upper_mask;

        for i in 0..n {
            let x = (self.mt[i] & upper_mask) + (self.mt[(i + 1) % n] & lower_mask);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= a;
            }
            self.mt[i] = self.mt[(i + m) % n] ^ x_a;
        }
        self.index = 0;
    }
}

/// PKCS#7 padding.
///
/// See challenge 9.
pub fn pkcs7_pad(bytes: &[u8], block_size: usize) -> Vec<u8> {
    if bytes.len() % block_size == 0 {
        return bytes.to_vec();
    }
    let pad_len = block_size - (bytes.len() % block_size);
    let mut padded = bytes.to_vec();
    padded.append(&mut vec![pad_len as u8; pad_len]);
    padded
}

/// Remove PKCS#7 padding.
pub fn pkcs7_unpad(bytes: &[u8]) -> Option<Vec<u8>> {
    let pad_len = bytes[bytes.len() - 1] as usize;
    if pad_len == 0 || pad_len > bytes.len() {
        return None;
    }
    let mut unpadded = bytes.to_vec();
    unpadded.truncate(unpadded.len() - pad_len);
    Some(unpadded)
}

/// PKCS#7 validation.
///
/// See challenge 15.
///
/// # Examples
/// ```
/// use cpr::utils::pkcs7_valid;
/// assert!(pkcs7_valid(b"ICE ICE BABY\x04\x04\x04\x04", 16));
/// assert!(!pkcs7_valid(b"ICE ICE BABY\x05\x05\x05\x05", 16));
/// assert!(!pkcs7_valid(b"ICE ICE BABY\x01\x02\x03\x04", 16));
/// ```
pub fn pkcs7_valid(bytes: &[u8], block_size: usize) -> bool {
    if bytes.len() % block_size != 0 {
        return false;
    }
    let pad_len = bytes[bytes.len() - 1] as usize;
    if pad_len == 0 || pad_len > block_size {
        return false;
    }
    bytes[bytes.len() - pad_len..]
        .iter()
        .all(|&b| b == pad_len as u8)
}

/// Generate a random key.
pub fn rand_bytes(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen()).collect()
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

/// Decode UTF-8 bytes in a more forgiving way.
pub fn utf8_decode(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        if *b < 0x80 {
            s.push(*b as char);
        } else {
            s.push_str(&format!("\\x{:02x}", b));
        }
    }
    s
}

/// Element-wise XOR of two byte sequences.
pub fn xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    b1.iter().zip(b2.iter()).map(|(b1, b2)| b1 ^ b2).collect()
}
