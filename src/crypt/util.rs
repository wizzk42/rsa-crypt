/*
 * Copyright (c) 2019 [j]karef GmbH. All rights reserved.
 */

use std::{fs::File, io::prelude::*, path::Path};

extern crate openssl;

use self::openssl::error::ErrorStack;
use openssl::{
    pkey::{Private, Public},
    rsa::{Padding, Rsa},
};
use std::error::Error;
use std::fs::read_to_string;

pub fn read_from_file(name: &str) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();

    let path = Path::new(name);
    let file = File::open(&path);

    if !file.is_err() {
        file.unwrap().read_to_end(&mut result).unwrap_or_else(|_| {
            result.clear();
            0
        });
    }
    result
}

pub fn load_rsa_private_key(private_key: &Vec<u8>, passphrase: &Vec<u8>) -> Result<Rsa<Private>, ErrorStack> {
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
        let k: &str = line.splitn(2, |c| *c as char == '=')
            .next()
            .unwrap();
        let v: &str = line.splitn(2, |c| *c as char == '=')
            .next()
            .unwrap();
        match k.trim() {
            "key" => {
                key = v;
            },
            "iv" => {
                iv = v;
            },
            "salt" => {
                salt = v;
            },
            _ => {
                // skip other keys
            }
        }
    }
    (key, iv, salt)
}

fn _encrypt_impl(
    public_key: &Rsa<Public>,
    plaintext: &Vec<u8>,
    mut ciphertext: &mut Vec<u8>,
) -> usize {
    ciphertext.resize(public_key.size() as usize, 0);

    public_key
        .public_encrypt(plaintext, &mut ciphertext, Padding::PKCS1_OAEP)
        .unwrap()
}

fn _decrypt_impl(
    private_key: &Rsa<Private>,
    plaintext: &mut Vec<u8>,
    ciphertext: &Vec<u8>,
) -> usize {
    plaintext.resize(private_key.size() as usize, 0);
    private_key
        .private_decrypt(ciphertext, plaintext, Padding::PKCS1_OAEP)
        .unwrap()
}

//#[allow(dead_code)]
//pub fn encrypt(keyfile: &str, plaintext: Vec<u8>, ciphertext: &mut Vec<u8>) -> usize {
//    let _key = load_rsa_public_key(&read_from_file(keyfile));
//
//    let mut size: usize = 0;
//
//    if _key.is_ok() {
//        size = _encrypt_impl(&_key.unwrap(), &plaintext, ciphertext);
//    }
//    size
//}
//
//#[allow(dead_code)]
//pub fn decrypt(
//    keyfile: &str,
//    passphrase: &str,
//    plaintext: &mut Vec<u8>,
//    ciphertext: Vec<u8>,
//) -> usize {
//    let _key = load_rsa_private_key(&read_from_file(keyfile), passphrase.as_bytes());
//
//    let mut size: usize = 0;
//
//    if _key.is_ok() {
//        size = _decrypt_impl(&_key.unwrap(), plaintext, &ciphertext);
//        plaintext.retain(|&i| i > 0);
//    }
//    size
//}
