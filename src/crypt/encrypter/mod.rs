///
///
///
pub mod aes;
pub mod rsa;

extern crate openssl;

pub use crate::crypt::api::encryptable::Encryptable;

use crate::crypt::{
    CryptOpts, CryptParams,
    api::{
        key::{BaseKeyType, Key},
    },
};

pub struct Encrypter<Algorithm> {
    encrypter: Algorithm,
}

impl<Algorithm> Encrypter<Algorithm> {}

impl<Algorithm, KeyType> Encryptable<KeyType> for Encrypter<Algorithm>
where
    Algorithm: Encryptable<KeyType>,
    KeyType: Clone + BaseKeyType,
{
    fn new(
        _key: &Key<KeyType>,
        _opts: &CryptOpts,
    ) -> Encrypter<Algorithm> {
        Encrypter {
            encrypter: Algorithm::new(_key, _opts),
        }
    }
    fn encrypt(
        &self,
        _plaintext: &[u8],
        _ciphertext: &mut Vec<u8>,
        _params: &CryptParams,
    ) -> usize {
        self.encrypter.encrypt(_plaintext, _ciphertext, _params)
    }
}
