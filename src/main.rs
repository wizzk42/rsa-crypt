///
///
///

use std::str::FromStr;

extern crate structopt;

use structopt::StructOpt;

extern crate rsa_crypt;

use crate::rsa_crypt::*;

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
    pub fn to_crypt_opts(&self, _algorithm: &Algorithm) -> CryptOpts {
        let mut res: CryptOpts = CryptOpts {
            algorithm: Some(_algorithm.clone()),
            aes: None,
            rsa: None,
        };

        let aes: AesOpts = AesOpts {
            mode: AesCipherMode::from_str(
                    &self.aesCipherMode.as_str()
                ).ok()
        };
        res.aes = Some(aes);
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
        p.salt = HexVec::from_bytes(self.salt.as_bytes().to_vec());
        p.passphrase = HexVec::from_bytes(self.passphrase.as_bytes().to_vec());
        p
    }
}

fn cmd_encrypt(_cli: &CryptCommandLine) -> Result<(), i32> {
    let opts: CryptOpts = _cli.to_crypt_opts(
        &Algorithm::from_str(&_cli.algorithm).unwrap_or(Algorithm::None)
    );
    let params: CryptParams = CryptParams::default();


    let mut ciphertext: Vec<u8> = vec![];
    let plaintext: Vec<u8> = vec![];

    let res = match Algorithm::from_str(_cli.algorithm.as_str()) {
        Ok(Algorithm::Aes) => {
            let (keydata, ivdata, saltdata) = load_aes_key(&read_from_file(&_cli.keyfile));
            let key: Key<AesSymmetricKey> = Key::new(
                &AesSymmetricKey::new(&keydata, &ivdata, &saltdata)
            );
            let encrypter: Encrypter<AesEncrypter> = Encrypter::new(&key, &opts);
            encrypter.encrypt(&plaintext, &mut ciphertext, &params)
        },
        Ok(Algorithm::Rsa) => {
            let keydata: Vec<u8> = load_rsa_key(&read_from_file(&_cli.keyfile));
            let key: Key<RsaAsymmetricKey> = Key::new(&RsaAsymmetricKey::new(&keydata));
            let encrypter: Encrypter<RsaEncrypter> = Encrypter::new(&key, &opts);
            encrypter.encrypt(&plaintext, &mut ciphertext, &params)
        },
        Ok(Algorithm::None) => { 0 },
        Err(()) => { 0 },
    };

    if res > 0 {
        Ok(())
    } else {
        Err(-2)
    }
}

fn cmd_decrypt(_cli: &CryptCommandLine) -> Result<(), i32> {

    let opts: CryptOpts = _cli.to_crypt_opts(&Algorithm::from_str(&_cli.algorithm).unwrap());
    let params: CryptParams = CryptParams::default();

    let ciphertext: Vec<u8> = vec![];
    let mut plaintext: Vec<u8> = vec![];

    let res = match Algorithm::from_str(_cli.algorithm.as_str()) {
        Ok(Algorithm::Aes) => {

            let (keydata, ivdata, saltdata) = load_aes_key(&read_from_file(&_cli.keyfile));

            let key: Key<AesSymmetricKey> = Key::new(
                &AesSymmetricKey::new(
                    &keydata,
                    &ivdata,
                    &saltdata
                )
            );
            let decrypter: Decrypter<AesDecrypter> = Decrypter::new(
                &key,
                &opts
            );
            decrypter.decrypt(
                &mut plaintext,
                &ciphertext,
                &params
            )
        },
        Ok(Algorithm::Rsa) => {
            let keydata = load_rsa_key(&read_from_file(&_cli.keyfile));
            let key: Key<RsaAsymmetricKey> = Key::new(
                &RsaAsymmetricKey::new(&keydata)
            );
            let decrypter: Decrypter<RsaDecrypter> = Decrypter::new(
                &key,
                &opts
            );
            decrypter.decrypt(
                &mut plaintext,
                &ciphertext,
                &params
            )
        },
        Ok(Algorithm::None) => { 0 },
        Err(()) => { 0 },
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
            println!("{:?}", res);
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
