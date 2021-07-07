///
///
///
use openssl::symm::{encrypt, encrypt_aead};

use crate::crypt::{
    api::{
        aes::{AesCipherMode, AesSymmetricKey},
        encryptable::Encryptable,
        key::Key,
        symmetric::SymmetricCryptableWithTag,
    },
    crypter::aes::CipherChooser,
    CryptOpts, CryptParams,
};

pub struct AesEncrypter {
    key: Key<AesSymmetricKey>,
    cipher: AesCipherMode,
    tag_buffer_size: usize,
}

impl AesEncrypter {}

impl CipherChooser for AesEncrypter {
    fn cipher(&self) -> &AesCipherMode {
        &self.cipher
    }
}

impl Encryptable<AesSymmetricKey> for AesEncrypter {
    fn new(
        _key: &Key<AesSymmetricKey>,
        _opts: &CryptOpts,
    ) -> Self {
        let cipher = _opts
            .clone()
            .aes
            .map(|aes_opts| -> AesCipherMode {
                match aes_opts.mode {
                    Some(m) => m,
                    None => AesCipherMode::Aes256Gcm,
                }
            })
            .unwrap();
        AesEncrypter {
            key: _key.clone(),
            cipher,
            tag_buffer_size: 16,
        }
    }
    fn encrypt(
        &self,
        _plaintext: &[u8],
        _ciphertext: &mut Vec<u8>,
        _params: &CryptParams,
    ) -> usize {
        let mut tag_buffer = vec![0; self.tag_buffer_size];
        _ciphertext.clear();

        let res: Result<Vec<u8>, _>;

        if self.key_len_hint() > self.key.key_ref().key_ref().len() {
            _ciphertext.append(b"invalid key length".to_vec().as_mut());
            return 0;
        }

        if (self.iv_len_hint().is_none() || self.iv_len_hint() > Some(0))
            && self.iv_len_hint() > Some(self.key.key_ref().iv_ref().len())
        {
            _ciphertext.append(b"invalid iv length".to_vec().as_mut());
            return 0;
        }

        if self.supports_aead() {
            res = encrypt_aead(
                self.choose_cipher_fn(),
                &self.key.key_ref().key_clone(),
                Some(&self.key.key_ref().iv_clone()),
                _params.aead.as_ref().unwrap(),
                &_plaintext,
                &mut tag_buffer,
            );
        } else {
            res = encrypt(
                self.choose_cipher_fn(),
                &self.key.key_ref().key_clone(),
                Some(&self.key.key_ref().iv_clone()),
                &_plaintext,
            );
        }
        _ciphertext.append(
            res.unwrap_or_else(|r| {
                print!("{:?}", r);
                vec![]
            })
            .as_mut(),
        );

        if !tag_buffer.is_empty() {
            _ciphertext.push(b':');
            _ciphertext.append(tag_buffer.as_mut());
        }
        _ciphertext.len()
    }
}

impl SymmetricCryptableWithTag for AesEncrypter {
    fn tag_buffer_size(
        &mut self,
        _tag_buffer_size: usize,
    ) -> &Self {
        self.tag_buffer_size = _tag_buffer_size;
        self
    }
}
