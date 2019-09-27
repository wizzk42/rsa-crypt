///
///
///

use std::str::FromStr;

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub enum Hash {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Ripemd160,
}

impl Hash {
    pub fn size(&self) -> usize {
        match *self {
            Hash::Sha224 => 24,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
            Hash::Sha3_224 => 24,
            Hash::Sha3_256 => 32,
            Hash::Sha3_384 => 48,
            Hash::Sha3_512 => 64,
            Hash::Ripemd160 => 20,
        }
    }
}

impl FromStr for Hash {
    type Err = ();
    fn from_str(_s: &str) -> Result<Hash, ()> {
        match _s.to_lowercase().trim() {
            "sha256" => Ok(Hash::Sha256),
            "sha384" => Ok(Hash::Sha384),
            "sha512" => Ok(Hash::Sha512),
            "sha3_224" => Ok(Hash::Sha3_224),
            "sha3_256" => Ok(Hash::Sha3_256),
            "sha3_384" => Ok(Hash::Sha3_384),
            "sha3_512" => Ok(Hash::Sha3_512),
            "ripemd160" => Ok(Hash::Ripemd160),
            _ => Err(()),
        }
    }
}
