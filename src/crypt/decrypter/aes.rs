///
///
///

extern crate openssl;

use openssl::{
    symm::{decrypt, decrypt_aead},
};

use crate::crypt::{
    CryptOpts,
    CryptParams,
    api::{
        aes::{
            AesCipherMode,
            AesSymmetricKey,
        },
        key::Key,
        decryptable::Decryptable,
        symmetric::SymmetricCryptableWithTag,
    },
    crypter::aes::CipherChooser,
};

pub struct AesDecrypter {
    key: Key<AesSymmetricKey>,
    cipher: AesCipherMode,
    tag_buffer_size: usize,
}

impl AesDecrypter {}

impl CipherChooser for AesDecrypter {
    fn cipher(&self) -> &AesCipherMode {
        &self.cipher
    }
}

impl Decryptable<AesSymmetricKey> for AesDecrypter {
    fn new(_key: &Key<AesSymmetricKey>, _opts: &CryptOpts) -> Self {
        AesDecrypter {
            key: _key.clone(),
            cipher: _opts.clone()
                .aes.unwrap().mode.unwrap_or(
                    AesCipherMode::Aes128Gcm
                ),
            tag_buffer_size: 32,
        }
    }
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &[u8], _params: &CryptParams) -> usize {
        let mut splitted_ciphertext = _ciphertext.splitn(
            2,
            |c: &u8| { *c == b':' },
        );

        let mut _effective_ciphertext = splitted_ciphertext.next().unwrap();
        let mut _effective_tagbuffer = splitted_ciphertext.next().unwrap_or(&[0]);

        _plaintext.clear();

        let res = match _params.aead {
            Some(_) => {
                decrypt_aead(
                    self.choose_cipher_fn(),
                    &self.key.key_ref().key_clone(),
                    Some(&self.key.key_ref().iv_clone()),
                    _params.aead.as_ref().unwrap(),
                    &_plaintext,
                    &_effective_tagbuffer,
                )
            },
            None => {
                decrypt(
                    self.choose_cipher_fn(),
                    &self.key.key_ref().key_clone(),
                    Option::Some(&self.key.key_ref().iv_clone()),
                    &_ciphertext,
                )
            }
        };
        _plaintext.append(res.unwrap_or_else(|_| vec![]).as_mut());
        _plaintext.len()
    }
}

impl SymmetricCryptableWithTag for AesDecrypter {
    fn tag_buffer_size(&mut self, _tag_buffer_size: usize) -> &Self {
        self.tag_buffer_size = _tag_buffer_size;
        self
    }
}
