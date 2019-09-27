///
///
///

use openssl::{
    pkcs5::pbkdf2_hmac,
    hash::MessageDigest,
    error::ErrorStack,
};

use crate::hash::Hash;

use super::{
    Algorithm,
    KeyDerivationOpts,
    KeyDerivationParameters,
};

pub fn generate(_params: &KeyDerivationParameters, _opts: &[KeyDerivationOpts]) -> Result<Vec<u8>, ErrorStack> {
    match _params.algorithm {
        Algorithm::None => panic!("No algorithm selected"),
        Algorithm::Pbkdf2 => pbkdf2(_params, _opts),
        Algorithm::Argon2d => argon2d(_params, _opts),
        Algorithm::Argon2i => argon2i(_params, _opts),
    }
}

fn pbkdf2(_params: &KeyDerivationParameters, _opts: &[KeyDerivationOpts]) -> Result<Vec<u8>, ErrorStack> {
    let mut _key: Vec<u8> = Vec::new();
    _key.resize(_params.hash.size(), 0x00);
    match pbkdf2_hmac(
        &_params.passphrase.to_bytes(),
        &_params.salt.to_bytes(),
        _params.iter,
        select_message_digest(&_params.hash),
        &mut _key,
    ) {
        Err(err) => Err(err),
        Ok(_) => Ok(_key),
    }
}

fn argon2i(_params: &KeyDerivationParameters, _opts: &[KeyDerivationOpts]) -> Result<Vec<u8>, ErrorStack> {
    let _key: Vec<u8> = Vec::new();
    Ok(_key)
}

fn argon2d(_params: &KeyDerivationParameters, _opts: &[KeyDerivationOpts]) -> Result<Vec<u8>, ErrorStack> {
    let _key: Vec<u8> = Vec::new();
    Ok(_key)
}

fn select_message_digest(_hash: &Hash) -> MessageDigest {
    match _hash {
        Hash::Sha224 => MessageDigest::sha224(),
        Hash::Sha256 => MessageDigest::sha256(),
        Hash::Sha384 => MessageDigest::sha384(),
        Hash::Sha512 => MessageDigest::sha512(),
        Hash::Sha3_224 => MessageDigest::sha3_224(),
        Hash::Sha3_256 => MessageDigest::sha3_256(),
        Hash::Sha3_384 => MessageDigest::sha3_384(),
        Hash::Sha3_512 => MessageDigest::sha3_512(),
        Hash::Ripemd160 => MessageDigest::ripemd160(),
    }
}
