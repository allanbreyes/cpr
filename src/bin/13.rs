// ECB cut-and-paste
use cpr::utils;
use std::{error::Error, str::FromStr, string::ToString};

const KEY: &[u8] = b"YELLOW SUBMARINE";

pub fn solve(_input: &str) -> Option<String> {
    let (_, block_size) = utils::detect_lengths(oracle, 100)?;

    // 0123456789abcdef | 0123456789abcdef | 0123456789abcdef | 0123456789abcdef
    // email=aaaaaaaaaa | bbbbbbbbbb@evil. | com&uid=10&role= | user
    let pt1 = b"aaaaaaaaaabbbbbbbbbb@evil.com".to_vec();
    let ct1 = oracle(pt1);

    // 0123456789abcdef | 0123456789abcdef | 0123456789abcdef | 0123456789abcdef
    // email=cccccccccc | admin00000000000 | &uid=10&role=use | r
    let admin_block = utils::pkcs7_pad(b"admin", block_size);
    let pt2: Vec<u8> = b"c"
        .repeat(block_size - b"email=".len())
        .iter()
        .chain(&admin_block)
        .cloned()
        .collect();

    let ct2 = oracle(pt2);

    // 0123456789abcdef | 0123456789abcdef | 0123456789abcdef | 0123456789abcdef
    // <-- ct1[0] ----> | <-- ct1[1] ----> | <-- ct1[2] ----> | <-- ct2[1] ---->
    let ct3: Vec<u8> = [
        ct1[..(block_size * 3)].to_vec(),
        ct2[(block_size)..(block_size * 2)].to_vec(),
    ]
    .iter()
    .flatten()
    .cloned()
    .collect();

    Some(base64::encode(ct3))
}

#[derive(Debug, PartialEq, Eq)]
struct Cookie {
    email: String,
    uid: u32,
    role: String,
}

impl FromStr for Cookie {
    type Err = Box<dyn Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.trim()
            .split('&')
            .filter_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                match key {
                    "email" | "role" | "uid" => {
                        Some::<(String, String)>((key.into(), value.into()))
                    }
                    _ => None,
                }
            })
            .fold(
                Ok(Cookie {
                    email: "".into(),
                    uid: 0,
                    role: "".into(),
                }),
                |cookie, (key, value)| {
                    let mut cookie = cookie?;
                    match key.as_str() {
                        "email" => cookie.email = value,
                        "uid" => cookie.uid = value.parse()?,
                        "role" => cookie.role = value,
                        _ => (),
                    }
                    Ok(cookie)
                },
            )
    }
}

impl ToString for Cookie {
    fn to_string(&self) -> String {
        format!("email={}&uid={}&role={}", self.email, self.uid, self.role)
    }
}

impl Cookie {
    fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Self, Box<dyn Error>> {
        let plaintext = utils::ecb(ciphertext, key, 16, true);
        String::from_utf8(plaintext)?.parse()
    }

    fn encrypt(&self, key: &[u8]) -> Vec<u8> {
        let plaintext = self.to_string().into_bytes();
        utils::ecb(&plaintext, key, 16, false)
    }

    fn is_admin(&self) -> bool {
        self.role == "admin"
    }

    fn profile_for(email: &str) -> Self {
        let email = email.replace('&', "").replace('=', "");
        Cookie {
            email,
            uid: 10, // Fake user ID lookup
            role: "user".into(),
        }
    }
}

fn oracle(input: Vec<u8>) -> Vec<u8> {
    Cookie::profile_for(&String::from_utf8(input).unwrap()).encrypt(KEY)
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = &cpr::read_data(13, false)?;
    let solution = cpr::solve!(13, solve, input).ok_or("no solution")?;
    let ciphertext = base64::decode(&solution)?;
    let cookie = Cookie::decrypt(&ciphertext, KEY)?;
    if cookie.is_admin() {
        eprintln!("{}=> {:?}{}", cpr::GREY, cookie, cpr::RESET);
        return Ok(());
    }
    Err("not admin".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "email=foo@bar.com&uid=10&role=user";

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let input = &cpr::read_data(13, false)?;
        let got = solve(input).ok_or("no result")?;
        let ciphertext = base64::decode(&got)?;
        let cookie = Cookie::decrypt(&ciphertext, KEY)?;
        assert!(cookie.is_admin());
        Ok(())
    }

    #[test]
    fn test_from_and_to_str() {
        let cookie: Cookie = EXAMPLE.parse().unwrap();
        assert_eq!(
            cookie,
            Cookie {
                email: "foo@bar.com".into(),
                uid: 10,
                role: "user".into(),
            }
        );
        let string = cookie.to_string();
        assert_eq!(string, EXAMPLE);
    }
}
