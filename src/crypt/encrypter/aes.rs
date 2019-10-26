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
        },
        key::Key,
        encryptable::Encryptable,
        symmetric::SymmetricCryptableWithTag,
    },
    crypter::aes::CipherChooser,
};

pub struct AesEncrypter {
    key: Key<AesSymmetricKey>,
    cipher: AesCipherMode,
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
                    None => AesCipherMode::Aes256Gcm
                }
            }).unwrap();
        AesEncrypter {
            key: _key.clone(),
            cipher,
            tag_buffer_size: 32
        }
    }
    fn encrypt(&self, _plaintext: &[u8], _ciphertext: &mut Vec<u8>, _params: &CryptParams) -> usize {
        let mut tag_buffer = vec![0; self.tag_buffer_size];
        _ciphertext.clear();

        let res = match _params.aead {
            Some(_) => {
                encrypt_aead(
                    self.choose_cipher_fn(),
                    &self.key.key_ref().key_clone(),
                    Some(&self.key.key_ref().iv_clone()),
                    _params.aead.as_ref().unwrap(),
                    &_plaintext,
                    &mut tag_buffer,
                )
            },
            None => {
                encrypt(
                    self.choose_cipher_fn(),
                    &self.key.key_ref().key_clone(),
                    Some(&self.key.key_ref().iv_clone()),
                    &_plaintext,
                )
            }
        };
        _ciphertext.append(res.unwrap_or_else(|_| vec![]).as_mut());

        if !tag_buffer.is_empty() {
            _ciphertext.push(b':');
            _ciphertext.append(tag_buffer.as_mut());
        }
        _ciphertext.len()
    }
}

impl SymmetricCryptableWithTag for AesEncrypter {
    fn tag_buffer_size(&mut self, _tag_buffer_size: usize) -> &Self {
        self.tag_buffer_size = _tag_buffer_size;
        self
    }
}
