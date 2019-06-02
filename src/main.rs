///
///
///

use std::{
    str::FromStr,
};

extern crate structopt;
use structopt::StructOpt;

extern crate rsa_crypt;
use crate::rsa_crypt::{
    hash,
    kdf,
    crypt,
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
}

impl CryptCommandLine {
    pub fn to_crypto_parameters(&self) -> crypt::CryptoParameters {
        let mut p = crypt::CryptoParameters::new();
        p.algorithm = crypt::Algorithm::from_str(&self.algorithm).unwrap_or(crypt::Algorithm::None);
        p.base64 = self.base64;
        p.passphrase =self.passphrase.as_bytes().to_vec();
        p
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

fn cmd_encrypt(_cli: &CryptCommandLine) -> Result<(), i32> {
    let crypt_cli = _cli.to_crypto_parameters();
    use crypt::{Encryptable};

    let key = crypt_cli.key;

    let plaintext = crypt_cli.input.borrow();
    let mut ciphertext = crypt_cli.output.borrow_mut();

    let res = match crypt_cli.algorithm {
        crypt::Algorithm::Aes => {
            let encrypter: crypt::Encrypter<crypt::AesEncrypter> = crypt::Encrypter::new(&key);
            encrypter.encrypt(
                &plaintext,
                &mut ciphertext,
            )
        },
        crypt::Algorithm::Rsa => {
            let encrypter: crypt::Encrypter<crypt::RsaEncrypter> = crypt::Encrypter::new(&key);
            encrypter.encrypt(
                &plaintext,
                &mut ciphertext,
            )
        },
        _ => 0
    };
    if res > 0 {
        println!("{:?}", ciphertext);
        Ok(())
    } else {
        Err(-2)
    }
}

fn cmd_decrypt(_cli: &CryptCommandLine) -> Result<(), i32> {
    let crypt_cli = _cli.to_crypto_parameters();
    use crypt::Decryptable;

    let key = crypt_cli.key;
    let passphrase = crypt_cli.passphrase;

    let ciphertext = crypt_cli.input.borrow();
    let mut plaintext = crypt_cli.output.borrow_mut();

    let res = match crypt_cli.algorithm {
        crypt::Algorithm::Aes => {
            let decrypter: crypt::Decrypter<crypt::AesDecrypter> = crypt::Decrypter::new(
                &key, &passphrase
            );
            decrypter.decrypt(
                &mut plaintext,
                &ciphertext,
            )
        },
        crypt::Algorithm::Rsa => {
            let decrypter: crypt::Decrypter<crypt::RsaDecrypter> = crypt::Decrypter::new(
                &key, &passphrase
            );
            decrypter.decrypt(
                &mut plaintext,
                &ciphertext,
            )
        },
        _ => 0
    };
    if res > 0 {
        println!("{:?}", plaintext);
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
