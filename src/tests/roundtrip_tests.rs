use crate::encrypter;
use crate::decrypter;
use crate::function;

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let private_keyfile: &str = "src/tests/fixtures/sample.priv.key";
    let public_keyfile: &str = "src/tests/fixtures/sample.pub.key";

    let plaintext: String = String::from("Test TXT");
    let mut ciphertext: Vec<u8> = Vec::new();

    public_key = _read_from_file(public_keyfile);
    private_key = _read_from_file(private_keyfile);

    let ciphertext_len: usize = encrypter::Encrypter::new(_public_key).encrypt(
        plaintext.as_bytes().to_vec(),
        &mut ciphertext,
    );
    assert!(ciphertext_len > 0);

    let mut decrypted_plaintext: Vec<u8> = Vec::new();
    let plaintext_len: usize = decrypter::Decrypter::new(_private_key).decrypt(
        &mut decrypted_plaintext,
        ciphertext,
    );
    assert!(plaintext_len > 0);
    assert_eq!(plaintext.as_bytes().to_vec(), decrypted_plaintext);
}
