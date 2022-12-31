use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{self, Write},
    process,
};

const STATIC_BASE_URL: &str = "https://cryptopals.com/static/challenge-data";
const TEMPLATE: &str = r###"use cpr::utils;
use std::error::Error;

pub fn solve(input: &str) -> Option<String> {
    None
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(CHALLENGE, false)?;
    cpr::solve!(CHALLENGE, solve, input).ok_or("no solution")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(CHALLENGE, false)?;
        let want = Some("TODO".into());
        let has = "TODO";
        let got = solve(input);
        assert_eq!(want, got);
        assert!(got.unwrap().contains(has));
        Ok(())
    }
}
"###;

fn parse_args() -> Result<u8, pico_args::Error> {
    let mut args = pico_args::Arguments::from_env();
    args.free_from_str()
}

fn safe_create_file(path: &str) -> Result<File, io::Error> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

pub fn fetch_data(challenge: u8) -> Result<File, Box<dyn Error>> {
    let cwd = std::env::current_dir()?;
    let url = format!("{}/{}.txt", STATIC_BASE_URL, challenge);
    let res = reqwest::blocking::get(&url)?;
    let mut out = File::create(cwd.join("data").join(format!("{:02}.txt", challenge)))?;
    if res.status() == reqwest::StatusCode::OK {
        let data = res.text()?;
        io::copy(&mut data.as_bytes(), &mut out)?;
    }
    Ok(out)
}

fn main() {
    let challenge = match parse_args() {
        Ok(challenge) => challenge,
        Err(_) => {
            eprintln!("Need to specify a challenge (as integer). example: `cargo scaffold 7`");
            process::exit(1);
        }
    };

    let challenge_padded = format!("{:02}", challenge);
    let data_path = format!("data/{}.txt", challenge_padded);
    let module_path = format!("src/bin/{}.rs", challenge_padded);

    let mut file = match safe_create_file(&module_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to create module file: {}", e);
            process::exit(1);
        }
    };

    match file.write_all(
        TEMPLATE
            .replace("CHALLENGE", &challenge.to_string())
            .as_bytes(),
    ) {
        Ok(_) => {
            println!("Created module file \"{}\"", &module_path);
        }
        Err(e) => {
            eprintln!("Failed to write module contents: {}", e);
            process::exit(1);
        }
    }

    match fetch_data(challenge) {
        Ok(_) => {
            println!("Created data file \"{}\"", &data_path);
        }
        Err(e) => {
            eprintln!("Failed to create data file: {}", e);
        }
    }
}
