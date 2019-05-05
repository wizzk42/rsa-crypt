use std::env;
use base64;

pub mod function;
use crate::function::_read_from_file;

pub mod encrypter;
pub mod decrypter;
use decrypter::{RsaDecrypter, Decryptable, Decrypter};
use encrypter::{RsaEncrypter, Encryptable, Encrypter};

pub mod tests;

fn help() {
    println!("Usage:");
    println!("-----------------------------------------------------");
    println!("\tdecrypt <private_key_pem> <passphrase> <ciphertext>");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        3 => {
            let filename = &args[1];
            let plaintext = &args[2];

            println!("Encrypting plaintext {} using key at {}", plaintext, filename);

            let mut ciphertext: Vec<u8> = Vec::new();
            let _key = _read_from_file(filename);
            let rsa: Encrypter<RsaEncrypter> = Encrypter::new(&_key);
            let _ciphertext_len = rsa.encrypt(
                &plaintext.as_bytes().to_vec(),
                &mut ciphertext,
            );

            println!("{}", base64::encode(&ciphertext.to_vec()))
        }
        4 => {
            let filename = &args[1];
            let passphrase = &args[2];

            let _key = _read_from_file(filename);

            let ciphertext = match base64::decode(&args[3]) {
                Err(_) => args[3].as_bytes().to_vec(),
                Ok(res) => res
            };

            let mut plaintext = Vec::new();
            let rsa: Decrypter<RsaDecrypter> = Decrypter::new(
                &_key, &passphrase.as_bytes().to_vec()
            );
            let _plaintext_len = rsa.decrypt(
                &mut plaintext,
                &ciphertext,
            );

            match String::from_utf8(plaintext) {
                Err(why) => panic!("Non UTF8 plaintext. Cannot handle that {}", why),
                Ok(result) => println!("{}", result)
            }
        }
        _ => {
            help();
        }
    }
}
