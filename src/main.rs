///
///
///

use std::str::FromStr;

extern crate structopt;
use structopt::StructOpt;

extern crate rsa_crypt;
use crate::rsa_crypt::{
    crypt,
    hash,
    kdf,
    util,
};

pub mod tests;

#[derive(Debug, StructOpt)]
#[structopt(name = "rsa_crypt", about = "rsa crypt command line arguments")]
enum CommandLineArguments {
    #[structopt(name="encrypt")]
    Encrypt(CryptCommandLine),
    #[structopt(name="decrypt")]
    Decrypt(CryptCommandLine),
    #[structopt(name="password")]
    Password(KdfCommandLine),
}

#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "crypt_cli", about = "crypt command options")]
#[allow(non_snake_case)]
struct CryptCommandLine {
    #[structopt(short = "a", long = "algorithm")]
    pub algorithm: String,
    #[structopt(short = "p", long = "passphrase")]
    pub passphrase: String,
    #[structopt(short = "b", long = "base64")]
    pub base64: bool,
    #[structopt(short = "k", long = "keyfile")]
    pub keyfile: String,
    #[structopt(short = "i", long = "input")]
    pub input: String,
    #[structopt(short = "o", long = "output")]
    pub output: String,
    #[structopt(long = "aes")]
    pub aesCipherMode: String,
    #[structopt(long = "aead")]
    pub aead: String,
}

impl CryptCommandLine {
    pub fn to_crypt_opts(&self, _algorithm: &crypt::api::algorithm::Algorithm) -> crypt::CryptOpts {
        let mut res: crypt::CryptOpts = crypt::CryptOpts {
            algorithm: Some(_algorithm.clone()),
            aes: None,
            rsa: None,
        };
        match _algorithm {
            crypt::api::algorithm::Algorithm::Aes => {
                let aes: crypt::AesOpts = crypt::AesOpts {
                    mode: crypt::api::aes::AesCipherMode::from_str(&self.aesCipherMode.as_str()).ok()
                };
                res.aes = Some(aes);
            },
            crypt::api::algorithm::Algorithm::Rsa => {
            }
        };
        res
    }
}

#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "kdf_cli", about = "crypt command options")]
struct KdfCommandLine {
    #[structopt(short = "a", long = "algorithm", default_value="pbkdf2")]
    pub algorithm: String,
    #[structopt(short = "h", long = "hash", default_value="sha256")]
    pub hash: String,
    #[structopt(short = "i", long = "iter", default_value="128000")]
    pub iter: usize,
    #[structopt(short = "s", long = "salt", default_value="saltysalt")]
    pub salt: String,
    #[structopt(short = "p", long = "passphrase")]
    pub passphrase: String,
}

impl KdfCommandLine {
    pub fn to_key_derivation_parameters(&self) -> kdf::KeyDerivationParameters {
        let mut p = kdf::KeyDerivationParameters::new();
        p.algorithm = kdf::Algorithm::from_str(&self.algorithm).unwrap_or(kdf::Algorithm::None);
        p.hash = hash::Hash::from_str(&self.hash).unwrap_or(hash::Hash::Sha3_512);
        p.iter = self.iter;
        p.salt =util:: hexdata::HexVec::from_bytes(self.salt.as_bytes().to_vec());
        p.passphrase = util::hexdata::HexVec::from_bytes(self.passphrase.as_bytes().to_vec());
        p
    }
}
fn load_key(_keyfile: &str) -> Vec<u8> {
    vec![]
}

fn cmd_encrypt(_cli: &CryptCommandLine) -> Result<(), i32> {

    use crypt::api::encryptable::Encryptable;
    let opts: crypt::CryptOpts = _cli.to_crypt_opts(&crypt::api::algorithm::Algorithm::from_str(&_cli.algorithm).unwrap());
    let params: crypt::CryptParams = crypt::CryptParams::new();


    let mut ciphertext: Vec<u8> = vec![];
    let plaintext: Vec<u8> = vec![];

    let res = match crypt::api::algorithm::Algorithm::from_str(_cli.algorithm.as_str()) {
        Ok(crypt::api::algorithm::Algorithm::Aes) => {
            let keydata: Vec<u8> = load_key(&_cli.keyfile);
            let ivdata: Vec<u8> = vec![];
            let saltdata: Vec<u8> = vec![0xde,0xad,0xbe, 0xef];
            let key: crypt::api::key::Key<crypt::api::aes::AesSymmetricKey> = crypt::api::key::Key::new(&crypt::api::aes::AesSymmetricKey::new(&keydata, &ivdata, &saltdata));
            let encrypter: crypt::encrypter::Encrypter<crypt::encrypter::aes::AesEncrypter> = crypt::encrypter::Encrypter::new(&key, &opts);
            let size = encrypter.encrypt(&plaintext, &mut ciphertext, &params);
            size
        },
        Ok(crypt::api::algorithm::Algorithm::Rsa) => {
            let keydata: Vec<u8> = load_key(&_cli.keyfile);
            let key: crypt::api::key::Key<crypt::api::rsa::RsaAsymmetricKey> = crypt::api::key::Key::new(&crypt::api::rsa::RsaAsymmetricKey::new(&keydata));
            let encrypter: crypt::encrypter::Encrypter<crypt::encrypter::rsa::RsaEncrypter> = crypt::encrypter::Encrypter::new(&key, &opts);
            let size = encrypter.encrypt(&plaintext, &mut ciphertext, &params);
            size
        },
        Err(()) => {
            0
        },
    };

    if res > 0 {
        Ok(())
    } else {
        Err(-2)
    }
}

fn cmd_decrypt(_cli: &CryptCommandLine) -> Result<(), i32> {
    use crypt::api::decryptable::Decryptable;

    let opts: crypt::CryptOpts = _cli.to_crypt_opts(&crypt::api::algorithm::Algorithm::from_str(&_cli.algorithm).unwrap());
    let params: crypt::CryptParams = crypt::CryptParams::new();

    let ciphertext: Vec<u8> = vec![];
    let mut plaintext: Vec<u8> = vec![];

    let res = match crypt::api::algorithm::Algorithm::from_str(_cli.algorithm.as_str()) {
        Ok(crypt::api::algorithm::Algorithm::Aes) => {

            let keydata: Vec<u8> = load_key(&_cli.keyfile);
            let ivdata: Vec<u8> = vec![];
            let saltdata: Vec<u8> = vec![0xde,0xad,0xbe, 0xef];

            let key: crypt::api::key::Key<crypt::api::aes::AesSymmetricKey> = crypt::api::key::Key::new(&crypt::api::aes::AesSymmetricKey::new(&keydata, &ivdata, &saltdata));
            let decrypter: crypt::decrypter::Decrypter<crypt::AesDecrypter> = crypt::decrypter::Decrypter::new(&key, &opts);
            let size = decrypter.decrypt(&mut plaintext, &ciphertext, &params);
            size
        },
        Ok(crypt::api::algorithm::Algorithm::Rsa) => {
            let keydata: Vec<u8> = load_key(&_cli.keyfile);
            let key: crypt::api::key::Key<crypt::api::rsa::RsaAsymmetricKey> = crypt::api::key::Key::new(&crypt::api::rsa::RsaAsymmetricKey::new(&keydata));
            let decrypter: crypt::decrypter::Decrypter<crypt::decrypter::rsa::RsaDecrypter> = crypt::decrypter::Decrypter::new(&key, &opts);
            let size = decrypter.decrypt(&mut plaintext, &ciphertext, &params);
            size
        },
        Err(()) => {
            0
        },
    };

    if res > 0 {
        Ok(())
    } else {
        Err(-2)
    }
}

fn cmd_password(_cli: &KdfCommandLine) -> Result<(), i32> {
    println!("{:?} {:?}", _cli, _cli.to_key_derivation_parameters());

    let opts: [kdf::KeyDerivationOpts; 0] = [];

    match kdf::generate(
        &_cli.to_key_derivation_parameters(),
        &opts.to_owned(),
    ) {
        Ok(res) => {
            println!("{:?}", *res);
            Ok(())
        }
        Err(err) => {
            println!("{:?}", err);
            Err(-1)
        }
    }
}

fn main() {
    let res = match CommandLineArguments::from_args() {
        CommandLineArguments::Encrypt(args) => {
            cmd_encrypt(&args)
        },
        CommandLineArguments::Decrypt(args) => {
            cmd_decrypt(&args)
        },
        CommandLineArguments::Password(args) => {
            cmd_password(&args)
        },
    };
    match res {
        Ok(()) => std::process::exit(0),
        Err(exit_code) => std::process::exit(exit_code)
    };
}
