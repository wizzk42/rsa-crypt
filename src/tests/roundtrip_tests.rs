#[cfg(test)]
extern crate rsa_crypt;

#[cfg(test)]
use rsa_crypt::read_from_file;
#[cfg(test)]
use rsa_crypt::{Encrypter, AesEncrypter, RsaEncrypter, Encryptable};
#[cfg(test)]
use rsa_crypt::{Decrypter, AesDecrypter, RsaDecrypter, Decryptable};

#[test]
fn test_rsa_encrypt_decrypt_roundtrip() {
    let private_keyfile: &str = "src/tests/fixtures/sample.rsa.priv.key";
    let public_keyfile: &str = "src/tests/fixtures/sample.rsa.pub.key";

    let plaintext: String = String::from("Test TXT");
    let mut ciphertext: Vec<u8> = Vec::new();

    let public_key = read_from_file(public_keyfile);
    let private_key = read_from_file(private_keyfile);

    let rsa_encrypter: Encrypter<RsaEncrypter> = Encrypter::new(&public_key);

    let ciphertext_len: usize = rsa_encrypter
        .encrypt(
            &plaintext.as_bytes().to_vec(),
            &mut ciphertext,
        );
    assert!(ciphertext_len > 0);

    let mut decrypted_plaintext: Vec<u8> = Vec::new();

    let rsa_decrypter: Decrypter<RsaDecrypter> = Decrypter::new(
        &private_key, &Vec::new(),
    );

    let plaintext_len: usize = rsa_decrypter
        .decrypt(&mut decrypted_plaintext, &ciphertext);
    assert!(plaintext_len > 0);
    assert_eq!(plaintext.as_bytes().to_vec(), decrypted_plaintext);
}

#[test]
#[ignore]
fn test_aes_encrypt_decrypt_roundtrip() {
    let keyfile: &str = "src/tests/fixtures/sample.aes.key";

    let plaintext: String = String::from("Test Text");
    let mut ciphertext: Vec<u8> = Vec::new();

    let key = read_from_file(keyfile);

    let aes_encrypter: Encrypter<AesEncrypter> = Encrypter::new(&key);

    let ciphertext_len: usize = aes_encrypter
        .encrypt(
            &plaintext.as_bytes().to_vec(),
            &mut ciphertext,
        );
    assert!(ciphertext_len > 0);

    let mut decrypted_plaintext: Vec<u8> = Vec::new();
    let aes_decrypter: Decrypter<AesDecrypter> = Decrypter::new(&key, &Vec::new());
    let plaintext_len: usize = aes_decrypter.decrypt(
        &mut decrypted_plaintext,
        &ciphertext,
    );

    assert!(plaintext_len > 0);
    assert_eq!(plaintext.as_bytes().to_vec(), decrypted_plaintext);
}

#[test]
#[should_panic]
fn test_aes_encrypt_fail_no_key() {
    let keyfile: &str = "src/tests/fixtures/sample.aes.key";

    let plaintext: String = String::from("Test Text");
    let mut ciphertext: Vec<u8> = Vec::new();

    let key = read_from_file(keyfile);

    let aes_encrypter: Encrypter<AesEncrypter> = Encrypter::new(&key);

    let ciphertext_len: usize = aes_encrypter
        .encrypt(
            &plaintext.as_bytes().to_vec(),
            &mut ciphertext,
        );
    assert!(ciphertext_len > 0);
}
