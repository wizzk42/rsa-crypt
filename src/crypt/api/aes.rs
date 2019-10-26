///
///
///

use std::str::FromStr;

use super::symmetric::SymmetricKey;
use super::ciphermodes::CipherBlockMode;

pub type AesSymmetricKey=SymmetricKey<Vec<u8>, Vec<u8>, Vec<u8>>;

#[derive(Clone, Debug)]
pub enum AesVariant {
    Aes128,
    Aes256,
}

#[derive(Clone, Debug)]
pub enum AesCipherMode {
    Aes128Cbc,
    Aes128Ccm,
    Aes128Ctr,
    Aes128Gcm,
    Aes128Xts,
    Aes256Cbc,
    Aes256Ccm,
    Aes256Ctr,
    Aes256Gcm,
    Aes256Xts
}

impl AesCipherMode {
    pub fn variant(&self) -> AesVariant {
        match self {
            Self::Aes128Cbc |
            Self::Aes128Ccm |
            Self::Aes128Ctr |
            Self::Aes128Gcm |
            Self::Aes128Xts => AesVariant::Aes128,
            Self::Aes256Cbc |
            Self::Aes256Ccm |
            Self::Aes256Ctr |
            Self::Aes256Gcm |
            Self::Aes256Xts => AesVariant::Aes256
        }
    }
    pub fn blockmode(&self) -> CipherBlockMode {
        match self {
            Self::Aes128Cbc => CipherBlockMode::Cbc,
            Self::Aes128Ccm => CipherBlockMode::Ccm,
            Self::Aes128Ctr => CipherBlockMode::Ctr,
            Self::Aes128Gcm => CipherBlockMode::Gcm,
            Self::Aes128Xts => CipherBlockMode::Xts,
            Self::Aes256Cbc => CipherBlockMode::Cbc,
            Self::Aes256Ccm => CipherBlockMode::Ccm,
            Self::Aes256Ctr => CipherBlockMode::Ctr,
            Self::Aes256Gcm => CipherBlockMode::Gcm,
            Self::Aes256Xts => CipherBlockMode::Xts
        }
    }
}

impl FromStr for AesCipherMode {
    type Err = ();

    fn from_str(_s: &str) -> Result<AesCipherMode, ()> {
        match _s {
            "aes-128-cbc" => Ok(AesCipherMode::Aes128Cbc),
            "aes-128-ccm" => Ok(AesCipherMode::Aes128Ccm),
            "aes-128-ctr" => Ok(AesCipherMode::Aes128Ctr),
            "aes-128-gcm" => Ok(AesCipherMode::Aes128Gcm),
            "aes-128-xts" => Ok(AesCipherMode::Aes128Xts),
            "aes-256-cbc" => Ok(AesCipherMode::Aes256Cbc),
            "aes-256-ccm" => Ok(AesCipherMode::Aes256Ccm),
            "aes-256-ctr" => Ok(AesCipherMode::Aes256Ctr),
            "aes-256-gcm" => Ok(AesCipherMode::Aes256Gcm),
            "aes-256-xts" => Ok(AesCipherMode::Aes256Xts),
            _ => Err(()),
        }
    }
}
