use std::{error::Error, fs};

pub mod utils;

pub const GREY: &str = "\x1b[1;30m";
pub const RESET: &str = "\x1b[0m";

#[macro_export]
macro_rules! solve {
    ($challenge: expr, $solver: ident, $input: expr) => {{
        use cpr::{GREY, RESET};
        use std::time::Instant;

        let start = Instant::now();
        let solution = $solver($input);
        let elapsed = start.elapsed();
        if let Some(ref ans) = solution {
            eprintln!(
                "{}#{:02} answer ({:?}):{}",
                GREY, $challenge, elapsed, RESET
            );
            println!("{}", ans);
        } else {
            eprintln!("#{:02} not yet solved", $challenge);
        }
        solution
    }};
}

pub fn read_data(challenge: u8, reflow: bool) -> Result<String, Box<dyn Error>> {
    let cwd = std::env::current_dir()?;
    let filepath = cwd.join("data").join(format!("{:02}.txt", challenge));
    let mut data = fs::read_to_string(filepath)?;
    if reflow {
        data = data.replace('\r', "").replace('\n', "");
    }
    Ok(data)
}
