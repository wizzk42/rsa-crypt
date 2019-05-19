/*
 * Copyright (c) 2019 [j]karef GmbH. All rights reserved.
 */

extern crate openssl;

use openssl::{
    pkey::Public,
    rsa::{Padding, Rsa},
    symm::{encrypt, encrypt_aead, Cipher},
};

use super::crypter::{
    Encryptable,
    asymmetric::AsymmetricEncryptable,
    symmetric::{
        SymmetricKey,
        AesCipherMode,
        SymmetricCryptableWithAead,
        SymmetricCryptableWithTag,
        SymmetricEncryptable,
        SymmetricEncryptableWithAead,
        SymmetricEnryptableWithTag,
    },
};
use crate::crypt::crypter::asymmetric::AsymmetricKey;
use crate::crypt::util::load_rsa_public_key;

pub struct Encrypter<Algorithm> {
    encrypter: Algorithm
}

impl<Algorithm> Encrypter<Algorithm> {}

impl<Algorithm> Encryptable for Encrypter<Algorithm> where Algorithm: Encryptable {
    fn new(_key: &Vec<u8>) -> Encrypter<Algorithm> {
        Encrypter { encrypter: Algorithm::new(_key) }
    }
    fn encrypt(&self, _plaintext: &Vec<u8>, _ciphertext: &mut Vec<u8>) -> usize {
        self.encrypter.encrypt(_plaintext, _ciphertext)
    }
}

pub struct RsaEncrypter {
    key: AsymmetricKey<Rsa<Public>>,
}

impl RsaEncrypter {}

impl Encryptable for RsaEncrypter {
    fn new(_key: &Vec<u8>) -> Self {
        RsaEncrypter {
            key: AsymmetricKey::new(
                &load_rsa_public_key(_key).unwrap()
            ),
        }
    }
    fn encrypt(&self, _plaintext: &Vec<u8>, _ciphertext: &mut Vec<u8>) -> usize {
        _ciphertext.resize(self.key.raw().size() as usize, 0);
        self.key.raw()
            .public_encrypt(_plaintext, _ciphertext, Padding::PKCS1_OAEP)
            .unwrap()
    }
}

impl AsymmetricEncryptable<Rsa<Public>> for RsaEncrypter {
    fn new_asymmetric(_key: &Rsa<Public>) -> Self {
        RsaEncrypter {
            key: AsymmetricKey::new(_key)
        }
    }
}

pub struct AesEncrypter {
    key: SymmetricKey<Vec<u8>>,
    cipher: AesCipherMode,
    aead: Option<Vec<u8>>,
    tag_buffer_size: usize,
}

impl AesEncrypter {

    fn choose_cipher_fn(&self) -> Cipher {
        match self.cipher {
            AesCipherMode::Aes128Cbc => {
                Cipher::aes_128_cbc()
            }
            AesCipherMode::Aes128Ctr => {
                Cipher::aes_128_ctr()
            }
            AesCipherMode::Aes128Gcm => {
                Cipher::aes_128_gcm()
            }
            AesCipherMode::Aes128Xts => {
                Cipher::aes_128_xts()
            }
            AesCipherMode::Aes256Cbc => {
                Cipher::aes_128_cbc()
            }
            AesCipherMode::Aes256Ctr => {
                Cipher::aes_256_ctr()
            }
            AesCipherMode::Aes256Gcm => {
                Cipher::aes_256_gcm()
            }
            AesCipherMode::Aes256Xts => {
                Cipher::aes_256_xts()
            }
        }
    }
}

impl Encryptable for AesEncrypter {
    fn new(_key: &Vec<u8>) -> Self {
        let iv: Vec<u8> = Vec::new();
        let salt: Vec<u8> = Vec::new();
        AesEncrypter {
            key: SymmetricKey::new(_key, &iv, &salt),
            cipher: AesCipherMode::Aes256Gcm,
            aead: None,
            tag_buffer_size: 32
        }
    }
    fn encrypt(&self, _plaintext: &Vec<u8>, _ciphertext: &mut Vec<u8>) -> usize {
        let mut tag_buffer = vec![0; self.tag_buffer_size];
        _ciphertext.clear();
        _ciphertext.append(
            match self.aead {
                Some(_) => {
                    encrypt_aead(
                        self.choose_cipher_fn(),
                        &self.key.raw(),
                        Option::Some(&self.key.iv()),
                        self.aead.as_ref().unwrap(),
                        &_plaintext,
                        &mut tag_buffer,
                    )
                }
                None => {
                    encrypt(
                        self.choose_cipher_fn(),
                        &self.key.raw(),
                        Option::Some(&self.key.iv()),
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

impl SymmetricEncryptable<SymmetricKey<Vec<u8>>, AesCipherMode> for AesEncrypter {
    fn new_symmetric(_key: &SymmetricKey<Vec<u8>>, _cipher: AesCipherMode) -> Self {
        AesEncrypter {
            key: _key.to_owned(),
            cipher: _cipher,
            aead: None,
            tag_buffer_size: 32,
        }
    }
}

impl SymmetricCryptableWithAead for AesEncrypter {
    fn aead(&mut self, _aead: &Option<Vec<u8>>) -> &Self {
        self.aead = _aead.clone();
        self
    }
}

impl SymmetricEncryptableWithAead<SymmetricKey<Vec<u8>>, AesCipherMode> for AesEncrypter {}

impl SymmetricCryptableWithTag for AesEncrypter {
    fn tag_buffer_size(&mut self, _tag_buffer_size: usize) -> &Self {
        self.tag_buffer_size = _tag_buffer_size;
        self
    }
}

impl SymmetricEnryptableWithTag<SymmetricKey<Vec<u8>>, AesCipherMode> for AesEncrypter {}
