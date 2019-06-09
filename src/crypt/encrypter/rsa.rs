///
///
///

extern crate openssl;

use openssl::{
    pkey::Public,
    rsa::{Padding, Rsa},
};

use crate::crypt::{
    CryptOpts,
    CryptParams,
    api::{
        rsa::RsaAsymmetricKey,
        encryptable::Encryptable,
        key::Key,
    },
};

pub struct RsaEncrypter {
    key: Key<RsaAsymmetricKey>,
}

impl RsaEncrypter {
    fn load_public_key(&self) -> Option<Rsa<Public>> {
        Rsa::public_key_from_pem(self.key.key_ref().key_ref()).ok()
    }
}

impl Encryptable<RsaAsymmetricKey> for RsaEncrypter {
    fn new(_key: &Key<RsaAsymmetricKey>, _opts: &CryptOpts) -> Self {
        RsaEncrypter { key: _key.to_owned() }
    }
    fn encrypt(&self, _plaintext: &Vec<u8>, _ciphertext: &mut Vec<u8>, _params: &CryptParams) -> usize {
        match self.load_public_key() {
            Some(k) => {
                _ciphertext.resize(k.size() as usize, 0);
                k.public_encrypt(_plaintext, _ciphertext, Padding::PKCS1_OAEP)
                    .unwrap()
            },
            None => 0
        }
    }
}
