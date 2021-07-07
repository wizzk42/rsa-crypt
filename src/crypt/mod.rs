///
///
///
pub mod api;
pub mod crypter;
pub mod decrypter;
pub mod encrypter;
pub mod types;
pub mod util;

use api::{algorithm::Algorithm, aes::AesCipherMode};

#[derive(Clone, Debug)]
pub struct AesOpts {
    pub mode: Option<AesCipherMode>,
}

impl Default for AesOpts {
    fn default() -> Self {
        AesOpts {
            mode: Some(AesCipherMode::Aes256Gcm),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RsaOpts {}

#[derive(Clone, Debug)]
pub struct CryptOpts {
    pub algorithm: Option<Algorithm>,
    pub aes: Option<AesOpts>,
    pub rsa: Option<RsaOpts>,
}

impl CryptOpts {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_algorithm(
        &mut self,
        _algorithm: Algorithm,
    ) -> &Self {
        self.algorithm = Some(_algorithm);
        self.aes = Some(AesOpts::default());
        self
    }
    pub fn with_aes(
        &mut self,
        _aes: AesOpts,
    ) -> &Self {
        self.aes = Some(_aes);
        self.rsa = None;
        self
    }
    pub fn with_rsa(
        &mut self,
        _rsa: RsaOpts,
    ) -> &Self {
        self.aes = None;
        self.rsa = Some(_rsa);
        self
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
impl Default for CryptOpts {
    fn default() -> Self {
        CryptOpts {
            algorithm: None,
            aes: None,
            rsa: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CryptParams {
    pub base64: bool,
    pub passphrase: Option<Vec<u8>>,
    pub aead: Option<Vec<u8>>,
}

impl CryptParams {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_base64(
        &mut self,
        _base64: bool,
    ) -> &Self {
        self.base64 = _base64;
        self
    }
    pub fn with_passphrase(
        &mut self,
        _passphrase: Vec<u8>,
    ) -> &Self {
        self.passphrase = Some(_passphrase);
        self
    }
    pub fn with_aead(
        &mut self,
        _aead: Vec<u8>,
    ) -> &Self {
        self.aead = Some(_aead);
        self
    }
}

impl Default for CryptParams {
    fn default() -> Self {
        CryptParams {
            base64: false,
            passphrase: None,
            aead: Some(vec![]),
        }
    }
}
