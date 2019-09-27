///
///
///

use super::key::BaseKeyType;

#[derive(Clone)]
pub struct SymmetricKey<KeyDataType, IvDataType, SaltDataType>
    where KeyDataType: Clone, IvDataType: Clone, SaltDataType: Clone {

    key: KeyDataType,
    iv: IvDataType,
    salt: SaltDataType,
}

impl<KeyDataType, IvDataType, SaltDataType> SymmetricKey<KeyDataType, IvDataType, SaltDataType>
    where KeyDataType: Clone, IvDataType: Clone, SaltDataType: Clone {

    pub fn new(_key: &KeyDataType, _iv: &IvDataType, _salt: &SaltDataType) -> Self {
        SymmetricKey {
            key: _key.clone(),
            iv: _iv.clone(),
            salt: _salt.clone(),
        }
    }
    pub fn key_ref(&self) -> &KeyDataType {
        &self.key
    }
    pub fn key_clone(&self) -> KeyDataType {
        self.key.clone()
    }
    pub fn iv_ref(&self) -> &IvDataType {
        &self.iv
    }
    pub fn iv_clone(&self) -> IvDataType {
        self.iv.clone()
    }
    pub fn salt_ref(&self) -> &SaltDataType {
        &self.salt
    }
    pub fn salt_clone(&self) -> SaltDataType {
        self.salt.clone()
    }
}

impl<KeyDataType, IvDataType, SaltDataType> BaseKeyType for SymmetricKey<KeyDataType, IvDataType, SaltDataType>
    where KeyDataType: Clone, IvDataType: Clone, SaltDataType: Clone {
}

pub trait SymmetricCryptableWithTag {
    fn tag_buffer_size(&mut self, _tag_buffer_size: usize) -> &Self;
}

pub trait SymmetricCryptableWithAead {
    fn aead(&mut self, _aead: &Option<Vec<u8>>) -> &Self;
}
