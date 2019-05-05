
use crate::decrypter;
use crate::encrypter;
use crate::function;

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let private_keyfile: &str = "src/tests/fixtures/sample.priv.key";
    let public_keyfile: &str = "src/tests/fixtures/sample.pub.key";

    let plaintext: String = String::from("Test TXT");
    let mut ciphertext: Vec<u8> = Vec::new();

    let public_key = function::_read_from_file(public_keyfile);
    let private_key = function::_read_from_file(private_keyfile);

    let ciphertext_len: usize = encrypter::RsaEncrypter::new(&public_key)
        .encrypt(&plaintext.as_bytes().to_vec(), &mut ciphertext);
    assert!(ciphertext_len > 0);

    let mut decrypted_plaintext: Vec<u8> = Vec::new();
    let plaintext_len: usize = decrypter::RsaDecrypter::new(&private_key, &Vec::new())
        .decrypt(&mut decrypted_plaintext, &ciphertext);
    assert!(plaintext_len > 0);
    assert_eq!(plaintext.as_bytes().to_vec(), decrypted_plaintext);
}
