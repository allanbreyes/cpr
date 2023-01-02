// Detect single-character XOR
use cpr::utils;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let mut best = utils::Candidate {
        score: 0.,
        value: String::new(),
    };
    input
        .trim()
        .lines()
        .filter_map(|line| {
            let bytes = hex::decode(line.trim()).ok()?;
            let (_key, candidate) = utils::crack_single_byte_xor(&bytes, utils::score_text);
            Some(candidate)
        })
        .for_each(|candidate| {
            let maybe = String::from_utf8(candidate.value).ok();
            if let Some(plaintext) = maybe {
                if candidate.score > best.score {
                    best.score = candidate.score;
                    best.value = plaintext;
                }
            }
        });
    Some(best.value.trim().to_string())
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(4, false)?;
    cpr::solve!(4, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(4, false)?;
        let want = Some("Now that the party is jumping".into());
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
