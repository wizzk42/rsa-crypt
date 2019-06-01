///
///
///

extern crate openssl;
use openssl::{
    error::ErrorStack,
    pkey::{Private, Public},
    rsa::{Padding, Rsa},
};

pub fn load_rsa_private_key(
    private_key: &Vec<u8>,
    passphrase: &Vec<u8>,
) -> Result<Rsa<Private>, ErrorStack> {
    Rsa::private_key_from_pem_passphrase(private_key, passphrase)
}

pub fn load_rsa_public_key(public_key: &Vec<u8>) -> Result<Rsa<Public>, ErrorStack> {
    Rsa::public_key_from_pem(public_key)
}

pub fn load_aes_key(_data: &Vec<u8>) -> (&str, &str, &str) {
    let mut key: &str = "";
    let mut iv: &str = "";
    let mut salt: &str = "";

    for line in _data.split(|c| *c as char == '\n') {
        let k: &str = std::str::from_utf8(
            line.splitn(2, |c| *c as char == '=')
                .next()
                .unwrap()
        ).unwrap();
        let v: &str = std::str::from_utf8(
            line.splitn(2, |c| *c as char == '=')
                .next()
                .unwrap()
        ).unwrap();
        match k.trim() {
            "key" => {
                key = v;
            }
            "iv" => {
                iv = v;
            }
            "salt" => {
                salt = v;
            }
            _ => {
                // skip other keys
            }
        }
    }
    (key, iv, salt)
}
