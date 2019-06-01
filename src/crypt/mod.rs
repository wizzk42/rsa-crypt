///
///
///

mod crypter;
mod encrypter;
mod decrypter;
mod util;

use std::str::FromStr;
use crate::util::hexdata;

pub use crypter::{
    Decryptable,
    Encryptable,
    asymmetric::AsymmetricKey,
    symmetric::SymmetricKey,
};
pub use decrypter::{
    Decrypter,
    AesDecrypter,
    RsaDecrypter,
};
pub use encrypter::{
    Encrypter,
    AesEncrypter,
    RsaEncrypter,
};
pub use util::{
    load_rsa_public_key,
    load_rsa_private_key,
};

pub use crypter::symmetric::AesCipherMode;

#[derive(Clone, Debug)]
pub enum Algorithm {
    None,
    Aes,
    Rsa,
}

impl FromStr for Algorithm {
    type Err = ();

    fn from_str(_s: &str) -> Result<Algorithm, ()> {
        return match _s {
            "aes" => Ok(Algorithm::Aes),
            "rsa" => Ok(Algorithm::Rsa),
            _ => Err(()),
        };
    }
}

#[derive(Clone, Debug)]
pub struct CryptoParameters {
    pub algorithm: Algorithm,
    pub key: hexdata::HexVec,
    pub passphrase: hexdata::HexVec,
    pub base64: bool,
    pub input: hexdata::HexVec,
    pub output: hexdata::HexVec,
}

impl CryptoParameters {
    pub fn new() -> Self {
        CryptoParameters {
            algorithm: Algorithm::None,
            key: hexdata::HexVec::empty(),
            passphrase: hexdata::HexVec::empty(),
            base64: false,
            input: hexdata::HexVec::empty(),
            output: hexdata::HexVec::empty(),
        }
    }
}
