/*
https://cryptopals.com/sets/1/challenges/4

Detect single-character XOR

One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
 */
use super::c03;
use super::utils;

pub fn solve(input: &str) -> String {
    let mut candidate = utils::Candidate {
        score: 0.,
        value: String::new(),
    };
    for line in input.lines() {
        let result = c03::solve(line);
        match result {
            Some(value) => {
                let score = utils::score_text(&value.as_bytes());
                if score > candidate.score {
                    candidate.score = score;
                    candidate.value = value;
                }
            }
            None => (),
        }
    }
    candidate.value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c04() {
        let input = include_str!("../data/4.txt");
        let result = solve(input);
        assert_eq!(result, "Now that the party is jumping\n");
    }
}
