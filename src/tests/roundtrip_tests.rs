# [cfg(test)]
use crate::function::_read_from_file;
# [cfg(test)]
use crate::encrypter::{Encrypter, RsaEncrypter, Encryptable};
# [cfg(test)]
use crate::decrypter::{RsaDecrypter, Decryptable, Decrypter};

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let private_keyfile: &str = "src/tests/fixtures/sample.priv.key";
    let public_keyfile: &str = "src/tests/fixtures/sample.pub.key";

    let plaintext: String = String::from("Test TXT");
    let mut ciphertext: Vec<u8> = Vec::new();

    let public_key = _read_from_file(public_keyfile);
    let private_key = _read_from_file(private_keyfile);

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
