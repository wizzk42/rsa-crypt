///
///
///

extern crate openssl;

use openssl::{
    pkey::Private,
    rsa::{Padding, Rsa},
};

use crate::crypt::{
    CryptOpts,
    CryptParams,
    api::{
        key::Key,
        decryptable::Decryptable,
        rsa::RsaAsymmetricKey,
    },
};

#[allow(dead_code)]
pub struct RsaDecrypter { key: Key<RsaAsymmetricKey>, opts: CryptOpts }

impl RsaDecrypter {
    fn load_rsa_private_key(&self, _passphrase: &Option<Vec<u8>>) -> Option<Rsa<Private>> {
        Rsa::private_key_from_pem_passphrase(
            self.key.key_ref().key_ref(), _passphrase.as_ref().unwrap()
        ).ok()
    }
}

impl Decryptable<RsaAsymmetricKey> for RsaDecrypter {
    fn new(_key: &Key<RsaAsymmetricKey>, _opts: &CryptOpts) -> Self {
        RsaDecrypter { key: _key.to_owned(), opts: _opts.to_owned() }
    }
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &[u8], _params: &CryptParams) -> usize {
        match self.load_rsa_private_key(&_params.passphrase) {
            Some(k) => {
                _plaintext.resize(k.size() as usize, 0);
                let size = k.private_decrypt(_ciphertext, _plaintext, Padding::PKCS1_OAEP)
                    .unwrap();
                _plaintext.retain(|&i| i > 0);
                size
            },
            None => 0,
        }
    }
}
