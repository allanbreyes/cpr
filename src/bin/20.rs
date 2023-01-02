// Break fixed-nonce CTR statistically
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
        let chars = cts
            .iter()
            .filter_map(|ct| if ct.len() > i { Some(ct[i]) } else { None })
            .collect::<Vec<u8>>();

        let (keybyte, _) = utils::crack_single_byte_xor(&chars, heuristic);
        keystream.push(keybyte);
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

fn heuristic(bytes: &[u8]) -> f32 {
    let mut score = utils::score_text(bytes);
    for byte in bytes {
        score += match byte {
            b' ' | b'a'..=b'z' | b',' => 5.,
            b'!' | b';' => 3.,
            _ => -5.,
        };
    }
    score
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(20, false)?;
    cpr::solve!(20, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(20, false)?;
        let has = "i'm rated \"R\"...this is a warning, ya better void / Poets are paranoid, DJ's D-stroyed";
        let got = solve(input);
        dbg!(&got);
        assert!(got.unwrap().contains(has));
        Ok(())
    }
}
