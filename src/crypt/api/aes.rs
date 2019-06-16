///
///
///

use std::str::FromStr;

use super::symmetric::SymmetricKey;
use super::ciphermodes::CipherBlockMode;

pub type AesSymmetricKey=SymmetricKey<Vec<u8>,Vec<u8>,Vec<u8>>;

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
