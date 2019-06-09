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
        aes::AesSymmetricKey,
        ciphermodes::CipherBlockMode,
        key::Key,
        decryptable::Decryptable,
        symmetric::{
            AesVariant,
            AesCipherMode,
            SymmetricCryptableWithAead,
            SymmetricCryptableWithTag,
        },
    },
    crypter::aes::CipherChooser,
};

pub struct AesDecrypter {
    key: Key<AesSymmetricKey>,
    cipher: AesCipherMode,
    aead: Option<Vec<u8>>,
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
            cipher: _opts.clone().aes.unwrap().mode.unwrap_or(AesCipherMode::Aes128Gcm(AesVariant::Aes128, CipherBlockMode::Gcm)),
            aead: None,
            tag_buffer_size: 32,
        }
    }
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &Vec<u8>, _params: &CryptParams) -> usize {
        let mut splitted_ciphertext = _ciphertext.splitn(
            2,
            |c: &u8| { *c == ':' as u8 },
        );

        let mut _effective_ciphertext = splitted_ciphertext.next().unwrap();
        let mut _effective_tagbuffer = splitted_ciphertext.next().unwrap_or(&[0]);

        //let mut tag_buffer = ;
        _plaintext.clear();
        _plaintext.append(
            match self.aead {
                Some(_) => {
                    decrypt_aead(
                        self.choose_cipher_fn(),
                        &self.key.key_ref().key_clone(),
                        Some(&self.key.key_ref().iv_clone()),
                        self.aead.as_ref().unwrap(),
                        &_plaintext,
                        &_effective_tagbuffer,
                    )
                }
                None => {
                    decrypt(
                        self.choose_cipher_fn(),
                        &self.key.key_ref().key_clone(),
                        Option::Some(&self.key.key_ref().iv_clone()),
                        &_ciphertext,
                    )
                }
            }.unwrap().as_mut()
        );
        _plaintext.len()
    }
}

impl SymmetricCryptableWithAead for AesDecrypter {
    fn aead(&mut self, _aead: &Option<Vec<u8>>) -> &Self {
        self.aead = _aead.to_owned();
        self
    }
}

impl SymmetricCryptableWithTag for AesDecrypter {
    fn tag_buffer_size(&mut self, _tag_buffer_size: usize) -> &Self {
        self.tag_buffer_size = _tag_buffer_size;
        self
    }
}
