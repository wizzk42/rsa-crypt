/*
 * Copyright (c) 2019 [j]karef GmbH. All rights reserved.
 */

extern crate openssl;

use openssl::{
    pkey::Private,
    rsa::{Padding, Rsa},
    symm::{decrypt, decrypt_aead, Cipher},
};

use super::crypter::{
    Decryptable,
    asymmetric::{AsymmetricKey, AsymmetricDecryptable},
    symmetric::{
        SymmetricKey,
        AesCipherMode,
        SymmetricCryptableWithAead,
        SymmetricCryptableWithTag,
        SymmetricDecryptable,
        SymmetricDecryptableWithAead,
        SymmetricDecryptableWithTag,
    },
};

use std::slice::SplitN;
use crate::crypt::util::load_rsa_private_key;

pub struct Decrypter<Algorithm> {
    decrypter: Algorithm
}

impl<Algorithm> Decrypter<Algorithm> {}

impl<Algorithm> Decryptable for Decrypter<Algorithm> where Algorithm: Decryptable {
    fn new(_key: &Vec<u8>, _passphrase: &Vec<u8>) -> Decrypter<Algorithm> {
        Decrypter { decrypter: Algorithm::new(_key, _passphrase) }
    }
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &Vec<u8>) -> usize {
        self.decrypter.decrypt(_plaintext, _ciphertext)
    }
}

pub struct RsaDecrypter { key: AsymmetricKey<Rsa<Private>> }

impl RsaDecrypter {}

impl Decryptable for RsaDecrypter {
    fn new(_key: &Vec<u8>, _passphrase: &Vec<u8>) -> Self {
        RsaDecrypter {
            key: AsymmetricKey::new(
                &load_rsa_private_key(
                    _key,
                    _passphrase,
                ).unwrap()
            )
        }
    }
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &Vec<u8>) -> usize {
        _plaintext.resize(self.key.raw().size() as usize, 0);
        let size = self.key.raw().private_decrypt(_ciphertext, _plaintext, Padding::PKCS1_OAEP).unwrap();
        _plaintext.retain(|&i| i > 0);
        size
    }
}

impl AsymmetricDecryptable<AsymmetricKey<Rsa<Private>>> for RsaDecrypter {
    fn new_asymmetric(_key: &AsymmetricKey<Rsa<Private>>) -> Self {
        RsaDecrypter {
            key: (*_key).clone()
        }
    }
}

pub struct AesDecrypter {
    key: SymmetricKey<Vec<u8>>,
    cipher: AesCipherMode,
    aead: Option<Vec<u8>>,
    tag_buffer_size: usize,
}

impl AesDecrypter {
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

impl Decryptable for AesDecrypter {
    fn new(_key: &Vec<u8>, _passphrase: &Vec<u8>) -> Self {
        let mut splitted = _key.split(
            |c: &u8| *c as char == ':'
        );
        let _key_bytes = splitted.next().unwrap().to_vec();
        let _iv_bytes = splitted.next().unwrap().to_vec();
        let _salt_bytes = splitted.next().unwrap().to_vec();
        AesDecrypter {
            key: SymmetricKey::new(
                &_key_bytes, &_iv_bytes, &_salt_bytes
            ),
            cipher: AesCipherMode::Aes256Gcm,
            aead: None,
            tag_buffer_size: 32,
        }
    }
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &Vec<u8>) -> usize {
        let mut splitted_ciphertext: SplitN<u8, fn(&u8) -> bool> = _ciphertext.splitn(
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
                        &self.key.raw(),
                        Option::Some(&self.key.iv()),
                        self.aead.as_ref().unwrap(),
                        &_plaintext,
                        &_effective_tagbuffer,
                    )
                }
                None => {
                    decrypt(
                        self.choose_cipher_fn(),
                        &self.key.raw(),
                        Option::Some(&self.key.iv()),
                        &_ciphertext,
                    )
                }
            }.unwrap().as_mut()
        );
        _plaintext.len()
    }
}

impl SymmetricDecryptable<SymmetricKey<Vec<u8>>, AesCipherMode> for AesDecrypter {
    fn new_symmetric(_key: &SymmetricKey<Vec<u8>>, _cipher: AesCipherMode) -> Self {
        AesDecrypter {
            key: _key.to_owned(),
            cipher: _cipher,
            aead: None,
            tag_buffer_size: 32,
        }
    }
}

impl SymmetricCryptableWithAead for AesDecrypter {
    fn aead(&mut self, _aead: &Option<Vec<u8>>) -> &Self {
        self.aead = _aead.to_owned();
        self
    }
}

impl SymmetricDecryptableWithAead<SymmetricKey<Vec<u8>>, AesCipherMode> for AesDecrypter {}

impl SymmetricCryptableWithTag for AesDecrypter {
    fn tag_buffer_size(&mut self, _tag_buffer_size: usize) -> &Self {
        self.tag_buffer_size = _tag_buffer_size;
        self
    }
}

impl SymmetricDecryptableWithTag<SymmetricKey<Vec<u8>>, AesCipherMode> for AesDecrypter {}
