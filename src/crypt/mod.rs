///
///
///

mod crypter;
mod encrypter;
mod decrypter;
mod util;
mod types;

use std::{
    cell,
    rc,
    str::FromStr,
};

pub use crypter::{
    Decryptable,
    Encryptable,
    asymmetric::AsymmetricKey,
    symmetric::{
        SymmetricKey,
        AesCipherMode,
    },
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
pub use types::*;
pub use util::{
    load_rsa_public_key,
    load_rsa_private_key,
};

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
    pub key: Vec<u8>,
    pub passphrase: Vec<u8>,
    pub base64: bool,
    pub input: ByteVecSharedPtr,
    pub output: ByteVecSharedPtr,
}

impl CryptoParameters {
    pub fn new() -> Self {
        CryptoParameters {
            algorithm: Algorithm::None,
            key: vec![],
            passphrase: vec![],
            base64: false,
            input: new_mut_byte_vec(vec![]),
            output: new_mut_byte_vec(vec![]),
        }
    }
}
