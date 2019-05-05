extern crate openssl;

use openssl::{
    pkey::Public,
    rsa::{Padding, Rsa},
};

pub trait Encryptable {
    fn new(_key: &Vec<u8>) -> Self;
    fn encrypt(&self, plaintext: &Vec<u8>, ciphertext: &mut Vec<u8>) -> usize;
}

pub struct Encrypter<T> {
    encrypter: T
}

impl<T> Encrypter<T> where T: Encryptable {
}

impl<T> Encryptable for Encrypter<T> where T: Encryptable {
    fn new(_key: &Vec<u8>) -> Encrypter<T> {
        Encrypter { encrypter: T::new(_key) }
    }
    fn encrypt(&self, _plaintext: &Vec<u8>, _ciphertext: &mut Vec<u8>) -> usize {
        self.encrypter.encrypt(_plaintext, _ciphertext)
    }
}

pub struct RsaEncrypter {
    key: Rsa<Public>,
}

impl RsaEncrypter {
}

impl Encryptable for RsaEncrypter {
    fn new(_key: &Vec<u8>) -> Self {
        RsaEncrypter {
            key: Rsa::public_key_from_pem(_key).unwrap(),
        }
    }
    fn encrypt(&self, _plaintext: &Vec<u8>, _ciphertext: &mut Vec<u8>) -> usize {
        _ciphertext.resize(self.key.size() as usize, 0);
        self.key
            .public_encrypt(_plaintext, _ciphertext, Padding::PKCS1_OAEP)
            .unwrap()
    }
}
