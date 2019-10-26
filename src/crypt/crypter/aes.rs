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
            _ => Cipher::aes_256_gcm()
        }
    }
}
