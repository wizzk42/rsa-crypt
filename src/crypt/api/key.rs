///
///
///
use crate::crypt::{CryptOpts, CryptParams};

pub trait BaseKeyType: Sized {}

#[derive(Clone)]
pub struct Key<KeyType: Clone + BaseKeyType>(KeyType);

impl<KeyType> Key<KeyType>
where
    KeyType: Clone + BaseKeyType,
{
    pub fn new(_data: &KeyType) -> Self {
        Key(_data.clone())
    }
    pub fn key_ref(&self) -> &KeyType {
        &self.0
    }
    pub fn key_clone(&self) -> KeyType {
        self.0.clone()
    }
}
impl<KeyType> BaseKeyType for Key<KeyType> where KeyType: Clone + BaseKeyType {}

pub trait Decryptable<KeyType>
where
    KeyType: Clone + BaseKeyType,
{
    fn new(_key: &Key<KeyType>, _opts: &CryptOpts) -> Self;
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &[u8], _params: &CryptParams)
        -> usize;
}
