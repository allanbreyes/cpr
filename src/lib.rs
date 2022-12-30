use std::{error::Error, fs, io};

pub mod utils;

pub const GREY: &str = "\x1b[1;30m";
pub const RESET: &str = "\x1b[0m";
const STATIC_BASE_URL: &str = "https://cryptopals.com/static/challenge-data";

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

pub fn fetch_data(challenge: u8) -> Result<(), Box<dyn Error>> {
    let url = format!("{}/{}.txt", STATIC_BASE_URL, challenge);
    let data = reqwest::blocking::get(&url)?.text()?;
    let cwd = std::env::current_dir()?;
    let mut out = fs::File::create(cwd.join("data").join(format!("{:02}", challenge)))?;
    io::copy(&mut data.as_bytes(), &mut out)?;
    Ok(())
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
