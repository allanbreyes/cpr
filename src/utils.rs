/// Scores plaintext according to character frequency.
///
/// # Examples
///
/// ```
/// use cpr::utils::score_text;
/// assert!(score_text("Hello World!") > score_text("ÜŔ ŮŔ Æ Æ Æ"));
/// ```
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
