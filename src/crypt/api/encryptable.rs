///
///
///
use super::key::{BaseKeyType, Key};
use crate::crypt::{CryptOpts, CryptParams};

pub trait Encryptable<KeyType>
where
    KeyType: Clone + BaseKeyType,
{
    fn new(_key: &Key<KeyType>, _opts: &CryptOpts) -> Self;
    fn encrypt(&self, _plaintext: &[u8], _ciphertext: &mut Vec<u8>, _opts: &CryptParams) -> usize;
}
