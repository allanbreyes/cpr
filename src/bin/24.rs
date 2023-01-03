// Create the MT19937 stream cipher and break it
use cpr::utils::{self, MT19937};
use rand::Rng;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let (matches, ans1) = part_one(input)?;
    let ans2 = part_two()?;
    Some(format!(
        "Part 1: {} ({})\nPart 2: {}",
        ans1,
        if matches { "OK" } else { "FAIL" },
        ans2,
    ))
}

// Recover a 16-bit seed from a MT19937 PRNG stream cipher
fn part_one(input: &str) -> Option<(bool, u16)> {
    let mut rng = rand::thread_rng();
    let seed = rng.gen_range(0..=u16::MAX);

    let cpt = input.trim().as_bytes();
    let pt = [
        (0..rng.gen_range(0..18))
            .map(|_| rng.gen_range(b'!'..b'z'))
            .collect::<Vec<u8>>(),
        cpt.to_vec(),
    ]
    .concat();
    let ct = encrypt(&pt, seed as u32);

    // The attacker is aware of the chosen plaintext (without random prefix) as
    // well as the returned ciphertext stream. We can assume that they also know
    // that a MT19937 PRNG with an unknown 16-bit key is used.
    let key = attack_seed(cpt, &ct)?;
    Some((seed == key, key))
}

// Detect if a password reset token was seeded from the current time
fn part_two() -> Option<u32> {
    let token = gen_token();

    // The attacker has the password reset token and access to a clock.
    attack_time(&token)
}

fn attack_seed(cpt: &[u8], ct: &[u8]) -> Option<u16> {
    let prefix_length = ct.len() - cpt.len();

    // Since the seed is small, let's just brute force it.
    for seed in 0..=(u16::MAX) {
        let mut prng = MT19937::from_seed(seed as u32);

        // Throw out the values used for the random prefix
        (0..prefix_length).for_each(|_| {
            prng.gen();
        });

        let pt = utils::prng_stream_cipher(&ct[prefix_length..], &mut prng);
        if cpt == pt {
            return Some(seed);
        }
    }
    None
}

fn attack_time(token: &[u8]) -> Option<u32> {
    let now = utils::now();
    let limit = now - 60_000; // 1 minute lookback
    let mut seed = now;
    while seed > limit {
        let mut prng = MT19937::from_seed(seed);
        if (0..4u32)
            .flat_map(|_| prng.gen().to_le_bytes().to_vec())
            .collect::<Vec<u8>>()
            == token
        {
            return Some(seed);
        }
        seed -= 1;
    }

    None
}

#[allow(dead_code)]
fn decrypt(ct: &[u8], seed: u32) -> Vec<u8> {
    let mut prng = MT19937::from_seed(seed);
    utils::prng_stream_cipher(ct, &mut prng)
}

fn encrypt(pt: &[u8], seed: u32) -> Vec<u8> {
    let mut prng = MT19937::from_seed(seed);
    utils::prng_stream_cipher(pt, &mut prng)
}

fn gen_token() -> Vec<u8> {
    let mut prng = MT19937::from_seed(utils::now());
    (0..4u32)
        .flat_map(|_| prng.gen().to_le_bytes().to_vec())
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(24, true)?;
    cpr::solve!(24, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_part_one() {
        let input = &cpr::read_data(24, true).unwrap();
        part_one(input).unwrap();
    }

    #[test]
    #[ignore]
    fn test_part_two() {
        part_two().unwrap();
    }

    #[test]
    fn test_encrypt_decrypt() {
        let seed = 0xbeef;
        let pt = b"YELLOW SUBMARINE";
        let ct = encrypt(pt, seed);
        let out = decrypt(&ct, seed);
        assert_eq!(&pt.to_vec(), &out);
    }
}
