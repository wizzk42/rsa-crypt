use openssl::pkcs5::pbkdf2_hmac;
use openssl::hash::MessageDigest;
use openssl::error::{Error, ErrorStack};

#[derive(Clone)]
pub enum Algorithm {
    Pbkdf2,
    Argon2d,
    Argon2i,
}

#[derive(Clone)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Ripemd160,
}

#[derive(Clone)]
pub enum KeyDerivationOpts {}

#[derive(Clone)]
pub struct Data {
    pub hash: Hash,
    pub pass: Vec<u8>,
    pub iv: Vec<u8>,
    pub iter: usize,
    pub salt: Vec<u8>,
}

pub fn generate(_algorithm: Algorithm, _data: &Data, _opts: &[KeyDerivationOpts]) -> Result<Box<Vec<u8>>, ErrorStack> {
    match _algorithm {
        Algorithm::Pbkdf2 => pbkdf2(_data, _opts),
        Algorithm::Argon2d => argon2d(_data, _opts),
        Algorithm::Argon2i => argon2i(_data, _opts),
    }
}

fn pbkdf2(_data: &Data, _opts: &[KeyDerivationOpts]) -> Result<Box<Vec<u8>>, ErrorStack> {
    let mut _key: Vec<u8> = Vec::new();
    let res: Result<(), ErrorStack> = pbkdf2_hmac(
        &_data.pass,
        &_data.salt,
        _data.iter,
        select_message_digest(&_data.hash),
        &mut _key,
    );

    if res.is_err() {
        Err(res.err().unwrap())
    } else {
        Ok(Box::new(_key))
    }
}

fn argon2i(_data: &Data, _opts: &[KeyDerivationOpts]) -> Result<Box<Vec<u8>>, ErrorStack> {
    let _key: Vec<u8> = Vec::new();
    Ok(Box::new(_key))
}

fn argon2d(_data: &Data, _opts: &[KeyDerivationOpts]) -> Result<Box<Vec<u8>>, ErrorStack> {
    let _key: Vec<u8> = Vec::new();
    Ok(Box::new(_key))
}

fn select_message_digest(_hash: &Hash) -> MessageDigest {
    match _hash {
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
