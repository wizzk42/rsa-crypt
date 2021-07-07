///
///
///
extern crate openssl;
use openssl::symm::Cipher;

use crate::crypt::api::aes::AesCipherMode;

pub trait CipherChooser {
    fn cipher(&self) -> &AesCipherMode;

    fn choose_cipher_fn(&self) -> Cipher {
        match self.cipher() {
            AesCipherMode::Aes128Cbc => Cipher::aes_128_cbc(),
            AesCipherMode::Aes128Ctr => Cipher::aes_128_ctr(),
            AesCipherMode::Aes128Gcm => Cipher::aes_128_gcm(),
            AesCipherMode::Aes128Xts => Cipher::aes_128_xts(),
            AesCipherMode::Aes256Cbc => Cipher::aes_128_cbc(),
            AesCipherMode::Aes256Ctr => Cipher::aes_256_ctr(),
            AesCipherMode::Aes256Gcm => Cipher::aes_256_gcm(),
            AesCipherMode::Aes256Xts => Cipher::aes_256_xts(),
            _ => Cipher::aes_256_gcm(),
        }
    }

    fn supports_aead(&self) -> bool {
        match self.cipher() {
            AesCipherMode::Aes128Cbc
            | AesCipherMode::Aes128Ctr
            | AesCipherMode::Aes256Cbc
            | AesCipherMode::Aes256Ctr
            | AesCipherMode::Aes128Xts
            | AesCipherMode::Aes256Xts => false,
            AesCipherMode::Aes128Ccm
            | AesCipherMode::Aes128Gcm
            | AesCipherMode::Aes256Ccm
            | AesCipherMode::Aes256Gcm => true,
        }
    }

    fn block_size_hint(&self) -> usize {
        self.choose_cipher_fn().block_size()
    }

    fn key_len_hint(&self) -> usize {
        self.choose_cipher_fn().key_len()
    }

    fn iv_len_hint(&self) -> Option<usize> {
        self.choose_cipher_fn().iv_len()
    }
}
