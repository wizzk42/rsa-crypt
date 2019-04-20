use std::{
    error::Error,
    path::Path,
    io::prelude::*,
    fs::File,
};

extern crate openssl;

use openssl::{
    rsa::{Rsa, Padding},
    pkey::{Public, Private},
};

fn _read_from_file(name: &str) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();

    let path = Path::new(name);

    let mut file: File = match File::open(&path) {
        Err(why) => panic!(
            "Cannot open file {} {}",
            path.display(),
            why.description()
        ),
        Ok(file) => file
    };

    match file.read_to_end(&mut result) {
        Err(why) =>
            panic!(
                "couldn't read key {}: {}",
                path.display(),
                why.description()
            ),
        Ok(result) => result
    };

    result
}

fn _load_private_key(private_key: &[u8], passphrase: &[u8]) -> Rsa<Private> {
    match Rsa::private_key_from_pem_passphrase(private_key, passphrase) {
        Err(why) => panic!("Cannot decrypt private key. {}", why),
        Ok(result) => result
    }
}

fn _load_public_key(public_key: &[u8]) -> Rsa<Public> {
    match Rsa::public_key_from_pem(public_key) {
        Err(why) => panic!("cannot load public key: {}", why),
        Ok(result) => result
    }
}

fn _encrypt_impl(public_key: &Rsa<Public>,
                 plaintext: &Vec<u8>,
                 mut ciphertext: &mut Vec<u8>) -> usize {
    ciphertext.resize(public_key.size() as usize, 0);

    let size = match public_key.public_encrypt(
        plaintext,
        &mut ciphertext,
        Padding::PKCS1_OAEP,
    ) {
        Err(why) => panic!("Encrypting plaintext failed: {}", why),
        Ok(size) => size
    };
    size
}

fn _decrypt_impl(private_key: &Rsa<Private>,
                 plaintext: &mut Vec<u8>,
                 ciphertext: &Vec<u8>) -> usize
{
    plaintext.resize(private_key.size() as usize, 0);
    let size = match private_key.private_decrypt(
        ciphertext,
        plaintext,
        Padding::PKCS1_OAEP,
    ) {
        Err(why) => panic!("Decrypting ciphertext failed. {}", why),
        Ok(size) => size
    };
    size
}

pub fn encrypt(keyfile: &str,
               plaintext: Vec<u8>,
               ciphertext: &mut Vec<u8>) -> usize {
    let _key = _load_public_key(
        &_read_from_file(keyfile)
    );
    let size: usize = _encrypt_impl(
        &_key,
        &plaintext,
        ciphertext,
    );
    size
}

pub fn decrypt(keyfile: &str,
               passphrase: &str,
               plaintext: &mut Vec<u8>,
               ciphertext: Vec<u8>) -> usize {
    let _key = _load_private_key(
        &_read_from_file(keyfile),
        passphrase.as_bytes(),
    );
    let size: usize = _decrypt_impl(
        &_key,
        plaintext,
        &ciphertext,
    );
    plaintext.retain(|&i| i > 0);
    size
}
