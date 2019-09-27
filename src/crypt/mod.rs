///
///
///

pub mod api;
pub mod crypter;
pub mod decrypter;
pub mod encrypter;
pub mod types;
pub mod util;

/*
pub use api::{
    decryptable::Decryptable,
    encryptable::Encryptable,
    algorithm::Algorithm,
    asymmetric::AsymmetricKey,
    aes::AesSymmetricKey,
    rsa::RsaAsymmetricKey,
    key::Key,
    symmetric::{
        SymmetricKey,
        AesCipherMode,
    },
}
*/

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
    pub mode: Option<api::aes::AesCipherMode>,
}

#[derive(Clone, Debug)]
pub struct RsaOpts {
}

#[derive(Clone, Debug)]
pub struct CryptOpts {
    pub algorithm: Option<api::algorithm::Algorithm>,
    pub aes: Option<AesOpts>,
    pub rsa: Option<RsaOpts>
}

impl CryptOpts {
    pub fn algorithm_ref(&self) -> &api::algorithm::Algorithm {
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
        Self::default()
    }
}

impl Default for CryptParams {
    fn default() -> Self {
        CryptParams {
            base64: false,
            passphrase: None,
            aead: new_mut_byte_vec(vec![]),
        }
    }
}
