//use crate::rsa_crypt::_read_from_file;
//
//#[test]
//fn test_encrypt_decrypt_roundtrip() {
//    let private_keyfile: &str = "src/tests/fixtures/sample.priv.key";
//    let public_keyfile: &str = "src/tests/fixtures/sample.pub.key";
//
//    let plaintext: String = String::from("Test TXT");
//    let mut ciphertext: Vec<u8> = Vec::new();
//
//    let ciphertext_len: usize = function::encrypt(
//        public_keyfile,
//        plaintext.as_bytes().to_vec(),
//        &mut ciphertext,
//    );
//    assert!(ciphertext_len > 0);
//
//    let mut decrypted_plaintext: Vec<u8> = Vec::new();
//    let plaintext_len: usize = function::decrypt(
//        private_keyfile,
//        "",
//        &mut decrypted_plaintext,
//        ciphertext,
//    );
//    assert!(plaintext_len > 0);
//    assert_eq!(plaintext.as_bytes().to_vec(), decrypted_plaintext);
//}
//
//#[test]
//fn test_encrypt_decrypt_no_public_key() {
//    let public_keyfile: &str = "src/tests/fixtures/no.such.public.key";
//
//    let plaintext: String = String::from("Test TXT");
//    let mut ciphertext: Vec<u8> = Vec::new();
//
//    let size: usize = function::encrypt(
//        public_keyfile,
//        plaintext.as_bytes().to_vec(),
//        &mut ciphertext,
//    );
//    assert_eq!(size, 0);
//}
//
//#[test]
//fn test_encrypt_decrypt_no_private_key() {
//    let private_keyfile: &str = "src/tests/fixtures/no.such.private.key";
//    let public_keyfile: &str = "src/tests/fixtures/sample.pub.key";
//
//    let plaintext: String = String::from("Test TXT");
//    let mut ciphertext: Vec<u8> = Vec::new();
//
//    let ciphertext_len: usize = function::encrypt(
//        public_keyfile,
//        plaintext.as_bytes().to_vec(),
//        &mut ciphertext,
//    );
//    assert!(ciphertext_len > 0);
//
//    let mut decrypted_plaintext: Vec<u8> = Vec::new();
//    let plaintext_len: usize = function::decrypt(
//        private_keyfile,
//        "",
//        &mut decrypted_plaintext,
//        ciphertext,
//    );
//    assert_eq!(plaintext_len, 0);
//}
