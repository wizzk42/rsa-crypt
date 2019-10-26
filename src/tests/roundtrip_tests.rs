///
///
///

#[cfg(test)]
extern crate rsa_crypt;

#[cfg(test)]
use rsa_crypt::*;

#[test]
fn test_rsa_encrypt_decrypt_roundtrip() {
    let mut crypt_opts: CryptOpts = CryptOpts::new();
    crypt_opts.with_algorithm(Algorithm::Rsa);

    let mut crypt_params: CryptParams = CryptParams::new();
    crypt_params.with_base64(true);
    crypt_params.with_passphrase("geheim1234".as_bytes().to_vec());

    let private_keyfile: &str = "src/tests/fixtures/sample.rsa.priv.key";
    let public_keyfile: &str = "src/tests/fixtures/sample.rsa.pub.key";

    let plaintext: String = String::from("Test TXT");
    let mut ciphertext: Vec<u8> = Vec::new();

    let public_key = read_from_file(public_keyfile);
    let private_key = read_from_file(private_keyfile);

    let pubkey = Key::new(&RsaAsymmetricKey::new(&public_key));
    let privkey = Key::new(&RsaAsymmetricKey::new(&private_key));

    let rsa_encrypter: Encrypter<RsaEncrypter> = Encrypter::new(&pubkey, &crypt_opts);

    let ciphertext_len: usize = rsa_encrypter.encrypt(
        &plaintext.as_bytes().to_vec(),
        &mut ciphertext,
        &crypt_params,
    );
    assert!(ciphertext_len > 0);

    let mut decrypted_plaintext: Vec<u8> = Vec::new();

    let rsa_decrypter: Decrypter<RsaDecrypter> = Decrypter::new(&privkey, &crypt_opts);

    let plaintext_len: usize =
        rsa_decrypter.decrypt(&mut decrypted_plaintext, &ciphertext, &crypt_params);

    assert!(plaintext_len > 0);
    assert_eq!(plaintext.as_bytes().to_vec(), decrypted_plaintext);
}

#[test]
fn test_aes_encrypt_decrypt_roundtrip() {
    let (keydata, ivdata, saltdata) = load_aes_key(&read_from_file("src/tests/fixtures/sample.aes.key"));

    let mut crypt_opts: CryptOpts = CryptOpts::new();
    crypt_opts.with_algorithm(Algorithm::Aes);

    let mut crypt_params: CryptParams = CryptParams::new();
    crypt_params.with_base64(true);
    crypt_params.with_passphrase("geheim1234".as_bytes().to_vec());
    crypt_params.with_aead("this is some aead".as_bytes().to_vec());

    let plaintext: String = String::from("Test Text");
    let mut ciphertext: Vec<u8> = Vec::new();

    let key = Key::new(&AesSymmetricKey::new(&keydata, &ivdata, &saltdata));

    let aes_encrypter: Encrypter<AesEncrypter> = Encrypter::new(&key, &crypt_opts);

    let ciphertext_len: usize = aes_encrypter.encrypt(
        &plaintext.as_bytes().to_vec(),
        &mut ciphertext,
        &crypt_params,
    );
    assert!(ciphertext_len > 0);

    println!("TEST: {:?}", ciphertext_len);
    println!("TEST: {:?}", ciphertext);

    let mut decrypted_plaintext: Vec<u8> = Vec::new();
    let aes_decrypter: Decrypter<AesDecrypter> = Decrypter::new(&key, &crypt_opts);
    let plaintext_len: usize =
        aes_decrypter.decrypt(&mut decrypted_plaintext, &ciphertext, &crypt_params);

    println!("TEST: {:?}", plaintext_len);
    println!("TEST: {:?}", decrypted_plaintext);

    assert!(plaintext_len > 0);
    assert_eq!(plaintext.as_bytes().to_vec(), decrypted_plaintext);
}

#[test]
#[should_panic]
fn test_aes_encrypt_fail_no_key() {
    let crypt_opts: CryptOpts = CryptOpts::default();
    let crypt_params: CryptParams = CryptParams::default();

    let ivdata: Vec<u8> = vec![];
    let saltdata: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];

    let keyfile: &str = "src/tests/fixtures/sample.aes.key";

    let plaintext: String = String::from("Test Text");
    let mut ciphertext: Vec<u8> = Vec::new();

    let keydata = read_from_file(keyfile);
    let key = Key::new(&AesSymmetricKey::new(&keydata, &ivdata, &saltdata));

    let aes_encrypter: Encrypter<AesEncrypter> = Encrypter::new(&key, &crypt_opts);

    let ciphertext_len: usize = aes_encrypter.encrypt(
        &plaintext.as_bytes().to_vec(),
        &mut ciphertext,
        &crypt_params,
    );
    assert!(ciphertext_len > 0);
}
