use crate::function;

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let private_keyfile: &str = "src/tests/fixtures/sample.priv.key";
    let public_keyfile: &str = "src/tests/fixtures/sample.pub.key";

    let plaintext: String = String::from("Test TXT");
    let mut ciphertext: Vec<u8> = Vec::new();

    let ciphertext_len: usize = function::encrypt(
        public_keyfile,
        plaintext.as_bytes().to_vec(),
        &mut ciphertext,
    );
    assert!(ciphertext_len > 0);

    let mut decrypted_plaintext: Vec<u8> = Vec::new();
    let plaintext_len: usize = function::decrypt(
        private_keyfile,
        "",
        &mut decrypted_plaintext,
        ciphertext,
    );
    assert!(plaintext_len > 0);
    assert_eq!(plaintext.as_bytes().to_vec(), decrypted_plaintext);
}
