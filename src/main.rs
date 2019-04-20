use std::env;
use base64;

pub mod function;
pub mod tests;

fn help() {
    println!("Usage:");
    println!("-----------------------------------------------------");
    println!("\tdecrypt <private_key_pem> <passphrase> <ciphertext>");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        3 => {
            let filename = &args[1];
            let plaintext = &args[2];

            println!("Encrypting plaintext {} using key at {}", plaintext, filename);

            let mut ciphertext: Vec<u8> = Vec::new();
            let _ciphertext_len = function::encrypt(
                filename,
                plaintext.as_bytes().to_vec(),
                &mut ciphertext,
            );

            println!("{}", base64::encode(&ciphertext.to_vec()))
        }
        4 => {
            let filename = &args[1];
            let passphrase = &args[2];
            let ciphertext = match base64::decode(&args[3]) {
                Err(_) => args[3].as_bytes().to_vec(),
                Ok(res) => res
            };

            let mut plaintext = Vec::new();
            let _plaintext_len = function::decrypt(
                filename,
                passphrase,
                &mut plaintext,
                ciphertext,
            );
            match String::from_utf8(plaintext) {
                Err(why) => panic!("Non UTF8 plaintext. Cannot handle that {}", why),
                Ok(result) => println!("{}", result)
            }
        }
        _ => {
            help();
        }
    }
}
