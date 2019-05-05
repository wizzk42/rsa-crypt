extern crate openssl;

use openssl::{
    pkey::Private,
    rsa::{Padding, Rsa},
};

pub struct RsaDecrypter { key: Rsa<Private> }

impl RsaDecrypter {
    pub fn new(_key: &Vec<u8>, passphrase: &Vec<u8>) -> RsaDecrypter {
        RsaDecrypter { key: Rsa::private_key_from_pem_passphrase(_key, passphrase).unwrap() }
    }

    pub fn decrypt(&self, plaintext: &mut Vec<u8>, ciphertext: &Vec<u8>) -> usize {
        plaintext.resize(self.key.size() as usize, 0);
        let size = self.key.private_decrypt(ciphertext, plaintext, Padding::PKCS1_OAEP).unwrap();
        plaintext.retain(|&i| i > 0);
        size
    }
}

