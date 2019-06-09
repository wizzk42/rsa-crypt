///
///
///

pub mod aes;
pub mod rsa;

use crate::crypt::{
    CryptOpts,
    CryptParams,
    api::{
        key::{BaseKeyType,Key},
        decryptable::Decryptable,
    }
};

pub struct Decrypter<Algorithm> {
    decrypter: Algorithm
}

impl<Algorithm> Decrypter<Algorithm> {}

impl<Algorithm, KeyType> Decryptable<KeyType> for Decrypter<Algorithm> where Algorithm: Decryptable<KeyType>, KeyType: Clone + BaseKeyType {
    fn new(_key: &Key<KeyType>, _opts: &CryptOpts) -> Decrypter<Algorithm> {
        Decrypter { decrypter: Algorithm::new(_key, _opts) }
    }
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &Vec<u8>, _params: &CryptParams) -> usize {
        self.decrypter.decrypt(_plaintext, _ciphertext, _params)
    }
}
