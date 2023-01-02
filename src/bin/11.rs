use cpr::utils;
use rand::{rngs::ThreadRng, Rng};
use std::error::Error;

const GUESSES: usize = 10;

pub fn solve(_input: &str) -> Option<String> {
    let mut rng = rand::thread_rng();
    let chosen_plaintext = &[41_u8; 16 * 3];
    let mut correct = 0;
    for _ in 0..GUESSES {
        let (ciphertext, ans) = encryption_oracle(chosen_plaintext, &mut rng);
        match (utils::detect_ecb(&ciphertext, 16), ans) {
            (true, Mode::ECB) => correct += 1,
            (false, Mode::CBC) => correct += 1,
            _ => (),
        }
    }
    Some(format!("{correct}/{GUESSES} correct guesses"))
}

#[allow(clippy::upper_case_acronyms)]
enum Mode {
    ECB,
    CBC,
}

fn encryption_oracle(data: &[u8], rng: &mut ThreadRng) -> (Vec<u8>, Mode) {
    let key = rand_block(rng);
    let mut plaintext = rand_pad(rng)
        .into_iter()
        .chain(data.iter().cloned())
        .chain(rand_pad(rng).into_iter())
        .collect::<Vec<u8>>();
    plaintext = utils::pkcs7_pad(&plaintext, 16);

    if rng.gen::<u8>() % 2 == 0 {
        (utils::ecb(&plaintext, &key, 16, false), Mode::ECB)
    } else {
        let iv = rand_block(rng);
        (utils::cbc(&plaintext, &key, &iv, 16, false), Mode::CBC)
    }
}

fn rand_block(rng: &mut ThreadRng) -> Vec<u8> {
    rng.gen::<[u8; 16]>().to_vec()
}

fn rand_pad(rng: &mut ThreadRng) -> Vec<u8> {
    (0..rng.gen_range(5..=10))
        .map(|_| rng.gen::<u8>())
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    cpr::solve!(11, solve, "").ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let want = Some("10/10 correct guesses".into());
        let got = solve("");
        assert_eq!(want, got);
        Ok(())
    }
}
