// ECB cut-and-paste
use cpr::utils;
use std::{error::Error, str::FromStr, string::ToString};

pub fn solve(_input: &str) -> Option<String> {
    let (key, oracle) = make_oracle();
    let ct = attack(&oracle)?;
    Some(hex::encode([&key[..], &ct[..]].concat()))
}

fn attack(oracle: &utils::Oracle) -> Option<Vec<u8>> {
    let (length, block_size) = utils::detect_lengths(oracle, 100)?;

    // 0123456789abcdef | 0123456789abcdef | 0123456789abcdef | 0123456789abcdef
    // email=aaaaaaaaaa | aaaaaaaaaa@evil. | com&uid=10&role= | user
    let target_length = block_size * 3 + b"user".len();
    let domain = b"@evil.com".to_vec();
    let pt1 = b"a"
        .repeat(target_length - length - domain.len())
        .iter()
        .chain(&domain)
        .cloned()
        .collect();
    let ct1 = oracle(pt1).ok()?;

    // 0123456789abcdef | 0123456789abcdef | 0123456789abcdef | 0123456789abcdef
    // email=aaaaaaaaaa | admin00000000000 | &uid=10&role=use | r
    let admin_block = utils::pkcs7_pad(b"admin", block_size);
    let pt2: Vec<u8> = b"a"
        .repeat(block_size - b"email=".len())
        .iter()
        .chain(&admin_block)
        .cloned()
        .collect();

    let ct2 = oracle(pt2).ok()?;

    // 0123456789abcdef | 0123456789abcdef | 0123456789abcdef | 0123456789abcdef
    // <-- ct1[0] ----> | <-- ct1[1] ----> | <-- ct1[2] ----> | <-- ct2[1] ---->
    let ct: Vec<u8> = [
        ct1[..(block_size * 3)].to_vec(),
        ct2[(block_size)..(block_size * 2)].to_vec(),
    ]
    .iter()
    .flatten()
    .cloned()
    .collect();

    Some(ct)
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
        let plaintext = utils::ecb(ciphertext, key, utils::Op::Decrypt);
        String::from_utf8(plaintext)?.parse()
    }

    fn encrypt(&self, key: &[u8]) -> Vec<u8> {
        let plaintext = self.to_string().into_bytes();
        utils::ecb(&plaintext, key, utils::Op::Encrypt)
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

fn make_oracle() -> (Vec<u8>, impl Fn(Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>) {
    let key = utils::rand_bytes(16);
    (key.clone(), move |input| {
        Ok(Cookie::profile_for(&String::from_utf8(input).unwrap()).encrypt(&key.clone()))
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let solution = cpr::solve!(13, solve, "").ok_or("no solution")?;
    let bytes = hex::decode(&solution)?;
    let (key, ciphertext) = bytes.split_at(16);
    let cookie = Cookie::decrypt(ciphertext, key)?;
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
        let got = solve("").ok_or("no result")?;
        let bytes = hex::decode(&got)?;
        let (key, ciphertext) = bytes.split_at(16);
        let cookie = Cookie::decrypt(ciphertext, key)?;
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
