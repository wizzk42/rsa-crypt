///
///
///

pub trait Encryptable {
    fn new(_key: &Vec<u8>) -> Self;
    fn encrypt(&self, plaintext: &Vec<u8>, ciphertext: &mut Vec<u8>) -> usize;
}

pub trait Decryptable {
    fn new(_key: &Vec<u8>, _passphrase: &Vec<u8>) -> Self;
    fn decrypt(&self, _plaintext: &mut Vec<u8>, _ciphertext: &Vec<u8>) -> usize;
}

#[derive(Clone)]
pub struct Key<KeyType> (KeyType);

impl<KeyType> Key<KeyType> where KeyType: Clone {
    pub fn new(_data: &KeyType) -> Self {
        Key(_data.clone())
    }
    pub fn raw(&self) -> &KeyType {
        &self.0
    }
}

pub enum CipherBlockMode {
    Cbc,
    Ccm,
    Cfb,
    Ctr,
    Gcm,
    Ofb,
    Xts,
}

pub mod asymmetric {
    #[derive(Clone)]
    pub struct AsymmetricKey<KeyType> {
        pub key: super::Key<KeyType>
    }

    impl<KeyType> AsymmetricKey<KeyType> where KeyType: Clone {
        pub fn new(_raw: &KeyType) -> Self {
            AsymmetricKey {
                key: super::Key::new(_raw)
            }
        }
        pub fn raw(&self) -> &KeyType {
            self.key.raw()
        }
    }

    pub trait AsymmetricEncryptable<Key>: super::Encryptable {
        fn new_asymmetric(_key: &Key) -> Self;
    }

    pub trait AsymmetricDecryptable<Key>: super::Decryptable {
        fn new_asymmetric(_key: &Key) -> Self;
    }
}

pub mod symmetric {
    #[derive(Clone)]
    pub struct SymmetricKey<KeyType> {
        key: super::Key<KeyType>,
        iv: Vec<u8>,
        salt: Vec<u8>,
    }

    impl<KeyType> SymmetricKey<KeyType> where KeyType: Clone {
        pub fn new(_raw: &KeyType, _iv: &Vec<u8>, _salt: &Vec<u8>) -> Self {
            SymmetricKey {
                key: super::Key::new(_raw),
                iv: _iv.clone(),
                salt: _salt.clone(),
            }
        }
        pub fn raw(&self) -> &KeyType {
            self.key.raw()
        }
        pub fn iv(&self) -> &Vec<u8> {
            &self.iv
        }
        pub fn salt(&self) -> &Vec<u8> {
            &self.salt
        }
    }

    pub enum AesVariant {
        Aes128,
        Aes256,
    }

    pub enum AesCipherMode {
        Aes128Cbc(AesVariant, super::CipherBlockMode),
        Aes128Ctr(AesVariant, super::CipherBlockMode),
        Aes128Gcm(AesVariant, super::CipherBlockMode),
        Aes128Xts(AesVariant, super::CipherBlockMode),
        Aes256Cbc(AesVariant, super::CipherBlockMode),
        Aes256Ctr(AesVariant, super::CipherBlockMode),
        Aes256Gcm(AesVariant, super::CipherBlockMode),
        Aes256Xts(AesVariant, super::CipherBlockMode),
    }

    pub trait SymmetricCryptableWithTag {
        fn tag_buffer_size(&mut self, _tag_buffer_size: usize) -> &Self;
    }

    pub trait SymmetricCryptableWithAead {
        fn aead(&mut self, _aead: &Option<Vec<u8>>) -> &Self;
    }

    pub trait SymmetricEncryptable<Key, CipherMode>: super::Encryptable {
        fn new_symmetric(_key: &Key, _cipher: CipherMode) -> Self;
    }

    pub trait SymmetricEncryptableWithAead<Key, CipherMode>: SymmetricCryptableWithAead + SymmetricEncryptable<Key, CipherMode> {}

    pub trait SymmetricEnryptableWithTag<Key, CipherMode>: SymmetricCryptableWithTag + SymmetricEncryptable<Key, CipherMode> {}

    pub trait SymmetricDecryptable<Key, CipherMode>: super::Decryptable {
        fn new_symmetric(_key: &Key, cipher: CipherMode) -> Self;
    }

    pub trait SymmetricDecryptableWithAead<Key, CipherMode>: SymmetricCryptableWithAead + SymmetricDecryptable<Key, CipherMode> {}

    pub trait SymmetricDecryptableWithTag<Key, CipherMode>: SymmetricCryptableWithTag + SymmetricDecryptable<Key, CipherMode> {}
}

