// Implement the MT19937 Mersenne Twister RNG
use cpr::utils;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    let mut prng = if input.is_empty() {
        utils::MT19937::new()
    } else {
        utils::MT19937::from_seed(input.parse().ok()?)
    };
    Some(
        (0..5)
            .map(|_| prng.gen().to_string())
            .collect::<Vec<String>>()
            .join("\n"),
    )
}

fn main() -> Result<(), Box<dyn Error>> {
    cpr::solve!(21, solve, "").ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        // Compare with: https://github.com/mztikk/mersenne-twister/blob/3366b0feeb1c3025526a61ad674c25b6d6c9390f/src/MT19937.rs#L255C6-L259
        let input = "5489";
        let want = Some(
            "3499211612
581869302
3890346734
3586334585
545404204"
                .into(),
        );
        let got = solve(input);
        assert_eq!(want, got);
        Ok(())
    }
}
