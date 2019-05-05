extern crate openssl;

use openssl::{
    pkey::Private,
    rsa::{Padding, Rsa},
};

pub trait Decryptable {
    fn new(_key: &Vec<u8>, _passphrase: &Vec<u8>) -> Self;
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &Vec<u8>) -> usize;
}

pub struct Decrypter<T> {
    decrypter: T
}

impl<T> Decrypter<T> where T: Decryptable {
}

impl<T> Decryptable for Decrypter<T> where T: Decryptable {
    fn new(_key: &Vec<u8>, _passphrase: &Vec<u8>) -> Decrypter<T> {
        Decrypter { decrypter: T::new(_key, _passphrase) }
    }
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &Vec<u8>) -> usize {
        self.decrypter.decrypt(_plaintext, _ciphertext)
    }
}

pub struct RsaDecrypter { key: Rsa<Private> }

impl RsaDecrypter {
}

impl Decryptable for RsaDecrypter {
    fn new(_key: &Vec<u8>, _passphrase: &Vec<u8>) -> Self {
        RsaDecrypter { key: Rsa::private_key_from_pem_passphrase(_key, _passphrase).unwrap() }
    }
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &Vec<u8>) -> usize {
        _plaintext.resize(self.key.size() as usize, 0);
        let size = self.key.private_decrypt(_ciphertext, _plaintext, Padding::PKCS1_OAEP).unwrap();
        _plaintext.retain(|&i| i > 0);
        size
    }
}
