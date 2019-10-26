///
///
///

pub mod aes;
pub mod rsa;

pub use crate::crypt::api::decryptable::Decryptable;

use crate::crypt::{
    CryptOpts,
    CryptParams,
    api::{
        key::{
            BaseKeyType,
            Key
        }
    }
};

pub struct Decrypter<Algorithm> {
    decrypter: Algorithm
}

impl<Algorithm> Decrypter<Algorithm> {}

impl<Algorithm, KeyType> Decryptable<KeyType> for Decrypter<Algorithm>
        where Algorithm: Decryptable<KeyType>, KeyType: Clone + BaseKeyType {
    fn new(_key: &Key<KeyType>, _opts: &CryptOpts) -> Decrypter<Algorithm> {
        Decrypter { decrypter: Algorithm::new(_key, _opts) }
    }
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &[u8], _params: &CryptParams) -> usize {
        self.decrypter.decrypt(_plaintext, _ciphertext, _params)
    }
}
