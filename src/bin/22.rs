// Crack an MT19937 seed
use cpr::utils;
use rand::Rng;
use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn solve(_input: &str) -> Option<String> {
    // "Wait a random number of seconds between, I don't know, 40 and 1000."
    // The prompt asks us to sleep, but let's just simulate the time jumps.
    // Ain't nobody got time for sleep!
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32
        + rand::thread_rng().gen_range(0..5_000); // See you in 2038

    // "Seeds the RNG with the current Unix timestamp"
    let mut prng = utils::MT19937::new(seed);

    // "Waits a random number of seconds again."
    let time = seed + rand::thread_rng().gen_range(0..5_000);

    // "Returns the first 32 bit output of the RNG."
    let val = prng.gen();

    attack(val, time)?.to_string().into()
}

fn attack(val: u32, time: u32) -> Option<u32> {
    // We could start at the median if we had an a priori, but let's just start
    // from "now" and work our way back up to some limit.
    let limit = time - 1000 * 60; // 1 minute lookback
    let mut seed = time;
    while seed > limit {
        let mut prng = utils::MT19937::new(seed);
        if prng.gen() == val {
            return Some(seed);
        }
        seed -= 1;
    }
    None
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(22, false)?;
    cpr::solve!(22, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(22, false)?;
        let got = solve(input);
        assert!(got.is_some());
        Ok(())
    }
}
