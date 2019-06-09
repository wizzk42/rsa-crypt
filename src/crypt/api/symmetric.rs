///
///
///

use super::{
    ciphermodes::CipherBlockMode,
    key::BaseKeyType,
};
use std::str::FromStr;

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

#[derive(Clone, Debug)]
pub enum AesVariant {
    Aes128,
    Aes256,
}

#[derive(Clone, Debug)]
pub enum AesCipherMode {
    Aes128Cbc(AesVariant, CipherBlockMode),
    Aes128Ccm(AesVariant, CipherBlockMode),
    Aes128Ctr(AesVariant, CipherBlockMode),
    Aes128Gcm(AesVariant, CipherBlockMode),
    Aes128Xts(AesVariant, CipherBlockMode),
    Aes256Cbc(AesVariant, CipherBlockMode),
    Aes256Ccm(AesVariant, CipherBlockMode),
    Aes256Ctr(AesVariant, CipherBlockMode),
    Aes256Gcm(AesVariant, CipherBlockMode),
    Aes256Xts(AesVariant, CipherBlockMode),
}
impl FromStr for AesCipherMode {
    type Err = ();

    fn from_str(_s: &str) -> Result<AesCipherMode, ()> {
        return match _s {
            "aes-128-cbc" => Ok(AesCipherMode::Aes128Cbc(AesVariant::Aes128, CipherBlockMode::Cbc)),
            "aes-128-ccm" => Ok(AesCipherMode::Aes128Ccm(AesVariant::Aes128, CipherBlockMode::Ccm)),
            "aes-128-ctr" => Ok(AesCipherMode::Aes128Ctr(AesVariant::Aes128, CipherBlockMode::Ctr)),
            "aes-128-gcm" => Ok(AesCipherMode::Aes128Ccm(AesVariant::Aes128, CipherBlockMode::Gcm)),
            "aes-128-xts" => Ok(AesCipherMode::Aes128Ccm(AesVariant::Aes128, CipherBlockMode::Xts)),
            "aes-256-cbc" => Ok(AesCipherMode::Aes128Cbc(AesVariant::Aes256, CipherBlockMode::Cbc)),
            "aes-256-ccm" => Ok(AesCipherMode::Aes128Ccm(AesVariant::Aes256, CipherBlockMode::Ccm)),
            "aes-256-ctr" => Ok(AesCipherMode::Aes128Ctr(AesVariant::Aes256, CipherBlockMode::Ctr)),
            "aes-256-gcm" => Ok(AesCipherMode::Aes128Ccm(AesVariant::Aes256, CipherBlockMode::Gcm)),
            "aes-256-xts" => Ok(AesCipherMode::Aes128Ccm(AesVariant::Aes256, CipherBlockMode::Xts)),
            _ => Err(()),
        };
    }
}

pub trait SymmetricCryptableWithTag {
    fn tag_buffer_size(&mut self, _tag_buffer_size: usize) -> &Self;
}

pub trait SymmetricCryptableWithAead {
    fn aead(&mut self, _aead: &Option<Vec<u8>>) -> &Self;
}
