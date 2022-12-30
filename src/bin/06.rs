// Break repeating-key XOR
use cpr::utils;
use std::cmp::Ordering;
use std::error::Error;

pub fn solve(ciphertext: &str) -> Option<String> {
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
    Some(best.trim().to_string())
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(6, false)?;
    cpr::solve!(6, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(6, false)?;
        let has = "play that funky music";
        let got = solve(input).unwrap();
        assert!(got.contains(has));
        Ok(())
    }
}
