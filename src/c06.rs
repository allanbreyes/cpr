/*
https://cryptopals.com/sets/1/challenges/6

Break repeating-key XOR

It is officially on, now.

This challenge isn't conceptually hard, but it involves actual error-prone
coding. The other challenges in this set are there to bring you up to speed.
This one is there to qualify you. If you can do this one, you're probably just
fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key
XOR.

Decrypt it.

Here's how:

- Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
- Write a function to compute the edit distance/Hamming distance between two
  strings. The Hamming distance is just the number of differing bits. The
  distance between:

    this is a test

    and

    wokka wokka!!!

  is 37. Make sure your code agrees before you proceed.

- For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second
  KEYSIZE worth of bytes, and find the edit distance between them. Normalize
  this result by dividing by KEYSIZE.
- The KEYSIZE with the smallest normalized edit distance is probably the key.
  You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4
  KEYSIZE blocks instead of 2 and average the distances.
- Now that you probably know the KEYSIZE: break the ciphertext into blocks of
  KEYSIZE length.
- Now transpose the blocks: make a block that is the first byte of every block,
  and a block that is the second byte of every block, and so on.
- Solve each block as if it was single-character XOR. You already have code to
  do this.
- For each block, the single-byte XOR key that produces the best looking
  histogram is the repeating-key XOR key byte for that block. Put them together
  and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking
repeating-key XOR ("Vigenere") statistically is obviously an academic exercise,
a "Crypto 101" thing. But more people "know how" to break it than can actually
break it, and a similar technique breaks something much more important.
 */
use super::utils;
use base64;
use std::cmp::Ordering;

pub fn solve(ciphertext: &str) -> String {
    let bytes = base64::decode(ciphertext.trim().replace('\n', "")).unwrap();

    // Find top candidates for key size
    let mut key_candidates: Vec<(f32, usize)> = (2..=40)
        .map(|key_size| {
            let chunks: Vec<&[u8]> = bytes.chunks(key_size).collect();
            let mut score: f32 = 0.0;
            for i in 0..chunks.len() - 1 {
                let dist = utils::hamming(chunks[i], chunks[i + 1]);
                score += dist as f32 / key_size as f32;
            }
            score /= (chunks.len() - 1) as f32;
            (score, key_size)
        })
        .collect();
    // TODO: refactor Candidate struct to use custom Ord trait
    key_candidates.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));

    // Transpose and solve blocks, then decrypt and score
    let mut candidates: Vec<(f32, String)> = key_candidates
        .iter()
        .take(5)
        .filter_map(|(_, key_size)| {
            let mut blocks: Vec<Vec<u8>> = vec![vec![]; *key_size];
            for i in 0..bytes.len() {
                blocks[i % key_size].push(bytes[i]);
            }

            let key: Vec<u8> = blocks
                .iter()
                .map(|block| {
                    let (key, _) = utils::crack_single_byte_xor(block, utils::score_text);
                    key
                })
                .collect();
            let plaintext = utils::repeating_key_xor(&bytes, &key);
            let score = utils::score_text(&plaintext);
            let result = String::from_utf8(plaintext);
            match result {
                Ok(result) => Some((score, result)),
                Err(_) => None,
            }
        })
        .collect();
    candidates.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));

    let (_, best) = candidates.iter().rev().take(1).next().unwrap();
    best.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c06() {
        let input = include_str!("../data/6.txt");
        let result: String = solve(input);
        assert!(result.contains("play that funky music"));
    }
}
