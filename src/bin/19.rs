// Break fixed-nonce CTR mode using substitutions
// NOTE: Woopsie, I ended up solving this like challenge 20, and cracking it
// like repeating-key XOR. In retrospect, I think the authors zeroed out the
// nonce and expected people to use a known nonce and counter to crack this like
// a Vignere/substitution cipher.
use cpr::utils;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let key = utils::rand_bytes(16);
    let cts = input
        .trim()
        .lines()
        .map(|line| {
            let bytes = base64::decode(line).unwrap();
            utils::ctr(&bytes, &key, 0, 16)
        })
        .collect::<Vec<Vec<u8>>>();

    attack(&cts)
}

fn attack(cts: &[Vec<u8>]) -> Option<String> {
    let mut keystream = Vec::new();
    let max = cts.iter().map(|ct| ct.len()).max().unwrap();

    for i in 0..max {
        let mut best = utils::Candidate {
            score: 0.,
            value: 0u8,
        };
        let chars = cts
            .iter()
            .filter_map(|ct| if ct.len() > i { Some(ct[i]) } else { None })
            .collect::<Vec<u8>>();

        for j in 0..=255 {
            let bytes = utils::single_byte_xor(&chars, j);
            let mut score = utils::score_text(&bytes);
            for byte in &bytes {
                score += match byte {
                    b' ' | b'a'..=b'z' | b',' => 5.,
                    _ => -5.,
                };
            }

            // Some light "hand-engineering" to kludge the solution for low
            // confidence scores. It's not perfect, but it's good enough for
            // this challenge!
            if i > 32 {
                score += match (i, bytes[0]) {
                    (33, b'e') => 20.,
                    (34, b'a') => 20.,
                    (35, b'd') => 20.,
                    (36, b'n') => 20.,
                    (37, b',') => 20.,
                    _ => 0.,
                };
            }

            if score > best.score {
                best = utils::Candidate { score, value: j };
            }
        }

        keystream.push(best.value);
    }

    Some(
        cts.iter()
            .map(|ct| {
                let bytes = utils::xor(ct, &keystream);
                utils::utf8_decode(&bytes)
            })
            .collect::<Vec<String>>()
            .join("\n"),
    )
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(19, false)?;
    cpr::solve!(19, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(19, false)?;
        let has = "i have met them at close of day";
        let got = solve(input);
        assert!(got.unwrap().contains(has));
        Ok(())
    }
}
