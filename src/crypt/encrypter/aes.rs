///
///
///
use openssl::{
    symm::{encrypt, encrypt_aead},
};

use crate::crypt::{
    CryptOpts,
    CryptParams,
    api::{
        aes::{
            AesCipherMode,
            AesSymmetricKey,
            AesVariant,
        },
        ciphermodes::CipherBlockMode,
        key::Key,
        encryptable::Encryptable,
        symmetric::{
            SymmetricCryptableWithAead,
            SymmetricCryptableWithTag,
        },
    },
    crypter::aes::CipherChooser,
};

pub struct AesEncrypter {
    key: Key<AesSymmetricKey>,
    cipher: AesCipherMode,
    aead: Option<Vec<u8>>,
    tag_buffer_size: usize,
}

impl AesEncrypter {
}

impl CipherChooser for AesEncrypter {
    fn cipher(&self) -> &AesCipherMode {
        &self.cipher
    }
}

impl Encryptable<AesSymmetricKey> for AesEncrypter {
    fn new(_key: &Key<AesSymmetricKey>, _opts: &CryptOpts) -> Self {
        let cipher = _opts.clone().aes.map(|aes_opts| -> AesCipherMode {
                match aes_opts.mode {
                    Some(m) => m,
                    None => AesCipherMode::Aes256Gcm(AesVariant::Aes256, CipherBlockMode::Gcm)
                }
            }).unwrap();
        AesEncrypter {
            key: _key.clone(),
            cipher: cipher,
            aead: None,
            tag_buffer_size: 32
        }
    }
    fn encrypt(&self, _plaintext: &Vec<u8>, _ciphertext: &mut Vec<u8>, _params: &CryptParams) -> usize {
        let mut tag_buffer = vec![0; self.tag_buffer_size];
        _ciphertext.clear();
        _ciphertext.append(
            match self.aead {
                Some(_) => {
                    encrypt_aead(
                        self.choose_cipher_fn(),
                        &self.key.key_ref().key_clone(),
                        Some(&self.key.key_ref().iv_clone()),
                        self.aead.as_ref().unwrap(),
                        &_plaintext,
                        &mut tag_buffer,
                    )
                }
                None => {
                    encrypt(
                        self.choose_cipher_fn(),
                        &self.key.key_ref().key_clone(),
                        Some(&self.key.key_ref().iv_clone()),
                        &_plaintext,
                    )
                }
            }.unwrap().as_mut()
        );
        if !tag_buffer.is_empty() {
            _ciphertext.push(':' as u8);
            _ciphertext.append(tag_buffer.as_mut());
        }
        _ciphertext.len()
    }
}

impl SymmetricCryptableWithAead for AesEncrypter {
    fn aead(&mut self, _aead: &Option<Vec<u8>>) -> &Self {
        self.aead = _aead.clone();
        self
    }
}

impl SymmetricCryptableWithTag for AesEncrypter {
    fn tag_buffer_size(&mut self, _tag_buffer_size: usize) -> &Self {
        self.tag_buffer_size = _tag_buffer_size;
        self
    }
}
