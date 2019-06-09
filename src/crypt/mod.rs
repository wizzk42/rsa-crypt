///
///
///

mod api;
mod crypter;
mod decrypter;
mod encrypter;
mod types;
mod util;

pub use api::{
    decryptable::Decryptable,
    encryptable::Encryptable,
    algorithm::Algorithm,
    asymmetric::AsymmetricKey,
    symmetric::{
        SymmetricKey,
        AesCipherMode,
    },
};

pub use decrypter::{
    Decrypter,
    aes::AesDecrypter,
    rsa::RsaDecrypter,
};
pub use encrypter::{
    Encrypter,
    aes::AesEncrypter,
    rsa::RsaEncrypter,
};
pub use types::*;
pub use util::load_aes_key;

#[derive(Clone, Debug)]
pub struct AesOpts {
    pub mode: Option<AesCipherMode>,
}

#[derive(Clone, Debug)]
pub struct RsaOpts {
}

#[derive(Clone, Debug)]
pub struct CryptOpts {
    pub algorithm: Option<Algorithm>,
    pub aes: Option<AesOpts>,
    pub rsa: Option<RsaOpts>
}

impl CryptOpts {
    pub fn new() -> Self {
        CryptOpts { algorithm: None, aes: None, rsa: None }
    }
    pub fn algorithm_ref(&self) -> &Algorithm {
        self.algorithm.as_ref().unwrap()
    }
    pub fn aes_ref(&self) -> &Option<AesOpts> {
        &self.aes
    }
    pub fn rsa_ref(&self) -> &Option<RsaOpts> {
       &self.rsa
    }
}

#[derive(Clone, Debug)]
pub struct CryptParams {
    pub base64: bool,
    pub passphrase: Option<Vec<u8>>,
    pub aead: ByteVecSharedPtr, // TODO: discuss
}

impl CryptParams {
    pub fn new() -> Self {
        CryptParams {
            base64: false,
            passphrase: None,
            aead: new_mut_byte_vec(vec![]),
        }
    }
}
