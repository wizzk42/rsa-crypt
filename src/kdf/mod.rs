///
///
///

pub mod kdf;

use crate::util::hexdata;

pub use kdf::generate;

use super::hash::Hash;
use std::str::FromStr;

const DEFAULT_SALT: &[u8] = &[0x05, 0x04, 0x01, 0x07];
const DEFAULT_ITER: usize = 128000;
const DEFAULT_MAX_THREADS: usize = 1;
const DEFAULT_MAX_MEM: usize = 1024 * 1024 * 1024;

#[derive(Clone, Debug)]
pub enum Algorithm {
    None,
    Pbkdf2,
    Argon2d,
    Argon2i,
}

impl FromStr for Algorithm {
    type Err = ();
    fn from_str(src: &str) -> Result<Algorithm, ()> {
        match src.to_lowercase().trim() {
            "pbkdf2" => Ok(Algorithm::Pbkdf2),
            "argon2d" => Ok(Algorithm::Argon2d),
            "argon2i" => Ok(Algorithm::Argon2i),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeyDerivationParameters {
    pub algorithm: Algorithm,
    pub hash: Hash,
    pub passphrase: hexdata::HexVec,
    pub iv: hexdata::HexVec,
    pub iter: usize,
    pub salt: hexdata::HexVec,
    pub max_threads: usize,
    pub max_mem: usize,
}

impl KeyDerivationParameters {
    pub fn new() -> Self {
        KeyDerivationParameters {
            algorithm: Algorithm::None,
            hash: Hash::Sha3_512,
            passphrase: hexdata::HexVec::from_bytes(vec![]),
            iv: hexdata::HexVec::from_bytes(vec![]),
            iter: DEFAULT_ITER,
            salt: hexdata::HexVec::from_bytes(DEFAULT_SALT.to_vec()),
            max_threads: DEFAULT_MAX_THREADS,
            max_mem: DEFAULT_MAX_MEM,
        }
    }
}

#[derive(Clone, Debug)]
pub enum KeyDerivationOpts {}
