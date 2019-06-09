///
///
///
extern crate openssl;
use openssl::symm::Cipher;

use crate::crypt::api::{
    ciphermodes::CipherBlockMode,
    symmetric::{
        AesCipherMode,
        AesVariant,
    },
};

pub trait CipherChooser {

    fn cipher(&self) -> &AesCipherMode;

    fn choose_cipher_fn(&self) -> Cipher {
        match self.cipher() {
            AesCipherMode::Aes128Cbc(AesVariant::Aes128, CipherBlockMode::Cbc) => {
                Cipher::aes_128_cbc()
            }
            AesCipherMode::Aes128Ctr(AesVariant::Aes128, CipherBlockMode::Ctr) => {
                Cipher::aes_128_ctr()
            }
            AesCipherMode::Aes128Gcm(AesVariant::Aes128, CipherBlockMode::Gcm) => {
                Cipher::aes_128_gcm()
            }
            AesCipherMode::Aes128Xts(AesVariant::Aes128, CipherBlockMode::Xts) => {
                Cipher::aes_128_xts()
            }
            AesCipherMode::Aes256Cbc(AesVariant::Aes256, CipherBlockMode::Cbc) => {
                Cipher::aes_128_cbc()
            }
            AesCipherMode::Aes256Ctr(AesVariant::Aes256, CipherBlockMode::Ctr) => {
                Cipher::aes_256_ctr()
            }
            AesCipherMode::Aes256Gcm(AesVariant::Aes256, CipherBlockMode::Gcm) => {
                Cipher::aes_256_gcm()
            }
            AesCipherMode::Aes256Xts(AesVariant::Aes256, CipherBlockMode::Xts) => {
                Cipher::aes_256_xts()
            },
            _ => Cipher::aes_256_gcm()
        }
    }
}
