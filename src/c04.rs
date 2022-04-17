/*
https://cryptopals.com/sets/1/challenges/4

Detect single-character XOR

One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
 */
use super::c03;
use super::utils;

struct Candidate {
    score: u32,
    text: String,
}

pub fn solve(input: &str) -> String {
    let mut candidate = Candidate {
        score: 0,
        text: String::new(),
    };
    for line in input.lines() {
        let text = c03::solve(line);
        let score = utils::score_text(&text);
        if score > candidate.score {
            candidate = Candidate { score, text };
        }
    }
    candidate.text
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
