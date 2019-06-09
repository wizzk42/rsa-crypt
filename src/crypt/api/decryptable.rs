///
///
///

use super::key::{BaseKeyType,Key};
use crate::crypt::{CryptOpts,CryptParams};

pub trait Decryptable<KeyType> where KeyType: Clone + BaseKeyType {
    fn new(_key: &Key<KeyType>, _opts: &CryptOpts) -> Self;
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &Vec<u8>, _params: &CryptParams) -> usize;
}
