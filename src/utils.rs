pub fn score_text(text: &str) -> u32 {
    let mut score = 0;
    for c in text.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | ' ' => score += 1,
            _ => (),
        }
    }
    score
}
