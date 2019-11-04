///
///
///

#[cfg(test)]
extern crate rsa_crypt;

#[cfg(test)]
use rsa_crypt::crypt::api::keyitem::{
    SymmetricKey,
    KeyTrait,
    SymmetricKeyTrait
};

const SAMPLE_KEY_8: [u8;4] = [0,2^7,2^7+1,2^8-1];
const SAMPLE_IV_8: [u8;4] = [0,2^7+1,2^7+2,2^8-1];
const SAMPLE_SALT_8: [u8;4] = [0xff, 0xfe, 0xfd, 0xfc];

#[test]
fn  test_init_8() {
    let key: SymmetricKey<u8> = SymmetricKey::new(
        &SAMPLE_KEY_8,
        &SAMPLE_IV_8,
        &SAMPLE_SALT_8
    );
    assert!(key.key().is_some());
    assert!(key.iv().is_some());
    assert!(key.salt().is_some());
    assert_eq!(key.key().unwrap(), SAMPLE_KEY_8);
    assert_eq!(key.iv().unwrap(), SAMPLE_IV_8);
    assert_eq!(key.salt().unwrap(), SAMPLE_SALT_8);

    drop(key);
}

#[test]
fn test_fluent_init_8() {

    let mut partial_key: SymmetricKey<u8> = SymmetricKey::with_key(&SAMPLE_KEY_8);

    assert!(partial_key.key().is_some());
    assert!(partial_key.iv().is_none());
    assert!(partial_key.salt().is_none());

    let partial_key_with_iv = partial_key.and_iv(
        &SAMPLE_IV_8
    );

    assert!(partial_key_with_iv.key().is_some());
    assert!(partial_key_with_iv.iv().is_some());
    assert!(partial_key_with_iv.salt().is_none());

    let complete_key = partial_key_with_iv.and_salt(
        &SAMPLE_SALT_8
    );

    assert!(complete_key.key().is_some());
    assert!(complete_key.iv().is_some());
    assert!(complete_key.salt().is_some());
}

#[test]
fn test_fluent_auto_init_8() {

    let mut partial_key: SymmetricKey<u8> = SymmetricKey::with_key(&SAMPLE_KEY_8);

    assert!(partial_key.key().is_some());
    assert!(partial_key.iv().is_none());
    assert!(partial_key.salt().is_none());

    let partial_key_with_iv = partial_key.and_auto_iv(32);

    assert!(partial_key_with_iv.key().is_some());
    assert!(partial_key_with_iv.iv().is_some());
    assert!(partial_key_with_iv.iv().unwrap().len() == 32);
    assert!(partial_key_with_iv.salt().is_none());

    let complete_key = partial_key_with_iv.and_auto_salt(16);

    assert!(complete_key.key().is_some());
    assert!(complete_key.iv().is_some());
    assert!(complete_key.iv().unwrap().len() == 32);
    assert!(complete_key.salt().is_some());
    assert!(complete_key.salt().unwrap().len() == 16);
}

#[test]
fn  test_clone_8() {
    let key: SymmetricKey<u8> = SymmetricKey::new(
        &SAMPLE_KEY_8,
        &SAMPLE_IV_8,
        &SAMPLE_SALT_8
    );

    let clone: SymmetricKey<u8> = key.clone();

    assert!(key.key().is_some());
    assert!(key.iv().is_some());
    assert!(key.salt().is_some());

    assert_eq!(key.key(), clone.key());
    assert_eq!(key.iv(), clone.iv());
    assert_eq!(key.salt(), clone.salt());

    drop(key);
}
