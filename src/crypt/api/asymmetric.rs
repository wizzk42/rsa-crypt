///
///
///

use super::key::BaseKeyType;

#[derive(Clone)]
pub struct AsymmetricKey<KeyDataType: Clone> {
    key: KeyDataType,
}

impl<KeyDataType> AsymmetricKey<KeyDataType>
        where KeyDataType: Clone {
    pub fn new(_key: &KeyDataType) -> Self {
        AsymmetricKey { key: _key.clone() }
    }
    pub fn key_ref(&self) -> &KeyDataType {
        &self.key
    }
    pub fn key_clone(&self) -> KeyDataType {
        self.key.clone()
    }
}

impl<KeyDataType> BaseKeyType for AsymmetricKey<KeyDataType> where KeyDataType: Clone {}
