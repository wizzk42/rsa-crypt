/*
 *
 */

extern crate openssl;

use openssl::{
    pkey::Public,
    rsa::{Padding, Rsa},
};

pub struct RsaEncrypter { key: Rsa<Public> }

impl RsaEncrypter {
    pub fn new(_key: &Vec<u8>) -> RsaEncrypter {
        RsaEncrypter { key: Rsa::public_key_from_pem(_key).unwrap() }
    }

    pub fn encrypt(&self, plaintext: &Vec<u8>, ciphertext: &mut Vec<u8>) -> usize {
        ciphertext.resize(self.key.size() as usize, 0);
        self.key.public_encrypt(
            plaintext,
            ciphertext,
            Padding::PKCS1_OAEP,
        )
            .unwrap()
    }
}
