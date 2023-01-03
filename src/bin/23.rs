// Clone an MT19937 RNG from its output
use cpr::utils::MT19937;
use std::error::Error;

pub fn solve(_input: &str) -> Option<String> {
    let mut prng = MT19937::new();
    let mut cloned = clone(&mut prng);
    Some(
        (0..10)
            .filter_map(|_| {
                let x = prng.gen();
                let y = cloned.gen();
                if x == y {
                    Some(x.to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<String>>()
            .join("\n"),
    )
}

fn clone(prng: &mut MT19937) -> MT19937 {
    let n: usize = 624;
    let u: u32 = 11;
    let s: u32 = 7;
    let t: u32 = 15;
    let l: u32 = 18;
    let b: u32 = 0x9D2C5680;
    let c: u32 = 0xEFC60000;

    let mut cloned = MT19937::from_seed(0);

    // Collect ouputs for a batch and apply the inverse of the temper function
    for i in 0..n {
        let mut y = prng.gen();
        y = undo_right_shift_xor(y, l);
        y = undo_left_shift_xor(y, t, c);
        y = undo_left_shift_xor(y, s, b);
        y = undo_right_shift_xor(y, u);
        cloned.mt[i] = y;
    }

    cloned
}

// Oh good grief, I absolutely detest bit magic. (╯°□°）╯︵ ┻━┻
// The following code is mostly cargo-culted from other people's solutions.
fn undo_right_shift_xor(x: u32, shift: u32) -> u32 {
    let w = 32;
    let mut y = (u32::max_value() << (w - shift)) & x;

    for i in 1..=(w - shift) {
        let n = w - shift - i;
        let yi = y >> (w - i) & 1;
        let xi = x >> n & 1;
        y |= (xi ^ yi) << n;
    }
    y
}

fn undo_left_shift_xor(x: u32, shift: u32, mask: u32) -> u32 {
    let w = 32;
    let mut y = (u32::max_value() >> (w - shift)) & x;

    for i in 0..(w - shift) {
        let n = shift + i;
        let yi = y >> i & 1;
        let xi = x >> n & 1;
        let ci = mask >> n & 1;

        y |= (xi ^ (yi & ci)) << n;
    }
    y
}

fn main() -> Result<(), Box<dyn Error>> {
    cpr::solve!(23, solve, "").ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let got = solve("");
        // Anything less than 10 means that the cloned PRNG didn't match some
        // output of the original PRNG
        assert!(got.unwrap().lines().count() == 10);
        Ok(())
    }
}
