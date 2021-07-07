///
///
///

#[cfg(test)]
extern crate rsa_crypt;

#[cfg(test)]
use rsa_crypt::crypt::api::keyitem::{
    AsymmetricKey, PublicAsymmetricKeyTrait, PrivateAsymmetricKeyTrait,
};

#[rustfmt::skip]
const SAMPLE_PUBLIC_8: [u8;4] = [0,2^7,2^7+1,2^8-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_8: [u8;4] = [0,2^7,2^7+1,2^8-1];

#[rustfmt::skip]
const SAMPLE_PUBLIC_16: [u16;4] = [2^8+1,2^8+2,2^8+3,2^16-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_16: [u16;4] = [2^8+2,2^8+3,2^8+5,2^16-1];

#[rustfmt::skip]
const SAMPLE_PUBLIC_32: [u32;4] = [2^16+1,2^16+2,2^16+3,2^32-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_32: [u32;4] = [2^16+2,2^16+3,2^16+4,2^32-2];

#[rustfmt::skip]
const SAMPLE_PUBLIC_64: [u64;4] = [2^32+1,2^32+2,2^32+3,2^64-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_64: [u64;4] = [2^32+1,2^32+2,2^32+3,2^64-1];

#[rustfmt::skip]
const SAMPLE_PUBLIC_8_1: [u8;4] = [0,2^7,2^7+1,2^8-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_8_1: [u8;4] = [0,2^7+1,2^7+2,2^8-1];

#[rustfmt::skip]
const SAMPLE_PUBLIC_8_2: [u8;4] = [0,2^7,2^7+1,2^8-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_8_2: [u8;4] = [0,2^7,2^7+5,2^8-1];

#[rustfmt::skip]
const SAMPLE_PUBLIC_16_1: [u16;4] = [2^8+1,2^8+2,2^8+3,2^16-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_16_1: [u16;4] = [2^8+2,2^8+7,2^8+9,2^16-1];

#[rustfmt::skip]
const SAMPLE_PUBLIC_16_2: [u16;4] = [2^8+1,2^8+2,2^8+9,2^16-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_16_2: [u16;4] = [2^8+2,2^8+3,2^8+5,2^16-1];

#[rustfmt::skip]
const SAMPLE_PUBLIC_32_1: [u32;4] = [2^16+1,2^16+6,2^16+3,2^32-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_32_1: [u32;4] = [2^16+2,2^16+3,2^16+4,2^32-2];

#[rustfmt::skip]
const SAMPLE_PUBLIC_32_2: [u32;4] = [2^16+1,2^16+20,2^16+3,2^32-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_32_2: [u32;4] = [2^16+2,2^16+3,2^16+4,2^32-2];

#[rustfmt::skip]
const SAMPLE_PUBLIC_64_1: [u64;4] = [2^32+16,2^32+32,2^32+48,2^64-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_64_1: [u64;4] = [2^32+15,2^32+31,2^32+47,2^64-2];

#[rustfmt::skip]
const SAMPLE_PUBLIC_64_2: [u64;5] = [2^64-16,2^64-32,2^64+48,2^64+64,2^64-1];
#[rustfmt::skip]
const SAMPLE_PRIVATE_64_2: [u64;5] = [2^64-15,2^64-31,2^64+47,2^64+63,2^64-2];

#[test]
fn test_init_8() {
    let key: AsymmetricKey<u8> = AsymmetricKey::new(&SAMPLE_PUBLIC_8, &SAMPLE_PRIVATE_8);

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_some());
    assert!(key.public_key().unwrap() == SAMPLE_PUBLIC_8);
    assert!(key.private_key().unwrap() == SAMPLE_PRIVATE_8);

    drop(key);
}

#[test]
fn test_clone_8() {
    let key: AsymmetricKey<u8> = AsymmetricKey::new(&SAMPLE_PUBLIC_8, &SAMPLE_PRIVATE_8);
    let clone: AsymmetricKey<u8> = key.clone();

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_some());
    assert!(clone.public_key().is_some());
    assert!(clone.private_key().is_some());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

#[test]
fn test_init_only_public_8() {
    let key: AsymmetricKey<u8> = AsymmetricKey::only_public(&SAMPLE_PUBLIC_8);

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_none());
    assert!(key.public_key().unwrap() == SAMPLE_PUBLIC_8);

    drop(key);
}

#[test]
fn test_clone_only_public_8() {
    let key: AsymmetricKey<u8> = AsymmetricKey::only_public(&SAMPLE_PUBLIC_8);
    let clone: AsymmetricKey<u8> = key.clone();

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_none());
    assert!(clone.public_key().is_some());
    assert!(clone.private_key().is_none());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

#[test]
fn test_init_only_private_8() {
    let key: AsymmetricKey<u8> = AsymmetricKey::only_private(&SAMPLE_PRIVATE_8);

    assert!(key.public_key().is_none());
    assert!(key.private_key().is_some());
    assert!(key.private_key().unwrap() == SAMPLE_PRIVATE_8);

    drop(key);
}

#[test]
fn test_clone_only_private_8() {
    let key: AsymmetricKey<u8> = AsymmetricKey::only_private(&SAMPLE_PRIVATE_8);
    let clone: AsymmetricKey<u8> = key.clone();

    assert!(key.public_key().is_none());
    assert!(key.private_key().is_some());
    assert!(clone.public_key().is_none());
    assert!(clone.private_key().is_some());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

#[test]
fn test_init_16() {
    let key: AsymmetricKey<u16> = AsymmetricKey::new(&SAMPLE_PUBLIC_16, &SAMPLE_PRIVATE_16);

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_some());
    assert!(key.public_key().unwrap() == SAMPLE_PUBLIC_16);
    assert!(key.private_key().unwrap() == SAMPLE_PRIVATE_16);

    drop(key);
}

#[test]
fn test_clone_16() {
    let key: AsymmetricKey<u16> = AsymmetricKey::new(&SAMPLE_PUBLIC_16, &SAMPLE_PRIVATE_16);
    let clone: AsymmetricKey<u16> = key.clone();

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_some());
    assert!(clone.public_key().is_some());
    assert!(clone.private_key().is_some());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

#[test]
fn test_init_only_public_16() {
    let key: AsymmetricKey<u16> = AsymmetricKey::only_public(&SAMPLE_PUBLIC_16);

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_none());
    assert!(key.public_key().unwrap() == SAMPLE_PUBLIC_16);

    drop(key);
}

#[test]
fn test_clone_only_public_16() {
    let key: AsymmetricKey<u16> = AsymmetricKey::only_public(&SAMPLE_PUBLIC_16);
    let clone: AsymmetricKey<u16> = key.clone();

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_none());
    assert!(clone.public_key().is_some());
    assert!(clone.private_key().is_none());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

#[test]
fn test_init_only_private_16() {
    let key: AsymmetricKey<u16> = AsymmetricKey::only_private(&SAMPLE_PRIVATE_16);

    assert!(key.public_key().is_none());
    assert!(key.private_key().is_some());
    assert!(key.private_key().unwrap() == SAMPLE_PRIVATE_16);

    drop(key);
}

#[test]
fn test_clone_only_private_16() {
    let key: AsymmetricKey<u16> = AsymmetricKey::only_private(&SAMPLE_PRIVATE_16);
    let clone: AsymmetricKey<u16> = key.clone();

    assert!(key.public_key().is_none());
    assert!(key.private_key().is_some());
    assert!(clone.public_key().is_none());
    assert!(clone.private_key().is_some());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

/// 32bit

#[test]
fn test_init_32() {
    let key: AsymmetricKey<u64> = AsymmetricKey::new(&SAMPLE_PUBLIC_64, &SAMPLE_PRIVATE_64);

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_some());
    assert!(key.public_key().unwrap() == SAMPLE_PUBLIC_64);
    assert!(key.private_key().unwrap() == SAMPLE_PRIVATE_64);

    drop(key);
}

#[test]
fn test_clone_32() {
    let key: AsymmetricKey<u32> = AsymmetricKey::new(&SAMPLE_PUBLIC_32, &SAMPLE_PRIVATE_32);
    let clone: AsymmetricKey<u32> = key.clone();

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_some());
    assert!(clone.public_key().is_some());
    assert!(clone.private_key().is_some());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

#[test]
fn test_init_only_public_32() {
    let key: AsymmetricKey<u32> = AsymmetricKey::only_public(&SAMPLE_PUBLIC_32);

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_none());
    assert!(key.public_key().unwrap() == SAMPLE_PUBLIC_32);

    drop(key);
}

#[test]
fn test_clone_only_public_32() {
    let key: AsymmetricKey<u32> = AsymmetricKey::only_public(&SAMPLE_PUBLIC_32);
    let clone: AsymmetricKey<u32> = key.clone();

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_none());
    assert!(clone.public_key().is_some());
    assert!(clone.private_key().is_none());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

#[test]
fn test_init_only_private_32() {
    let key: AsymmetricKey<u32> = AsymmetricKey::only_private(&SAMPLE_PRIVATE_32);

    assert!(key.public_key().is_none());
    assert!(key.private_key().is_some());
    assert!(key.private_key().unwrap() == SAMPLE_PRIVATE_32);

    drop(key);
}

#[test]
fn test_clone_only_private_32() {
    let key: AsymmetricKey<u32> = AsymmetricKey::only_private(&SAMPLE_PRIVATE_32);
    let clone: AsymmetricKey<u32> = key.clone();

    assert!(key.public_key().is_none());
    assert!(key.private_key().is_some());
    assert!(clone.public_key().is_none());
    assert!(clone.private_key().is_some());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

/// 64bit

#[test]
fn test_init_64() {
    let key: AsymmetricKey<u64> = AsymmetricKey::new(&SAMPLE_PUBLIC_64, &SAMPLE_PRIVATE_64);

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_some());
    assert!(key.public_key().unwrap() == SAMPLE_PUBLIC_64);
    assert!(key.private_key().unwrap() == SAMPLE_PRIVATE_64);

    drop(key);
}

#[test]
fn test_clone_64() {
    let key: AsymmetricKey<u64> = AsymmetricKey::new(&SAMPLE_PUBLIC_64, &SAMPLE_PRIVATE_64);
    let clone: AsymmetricKey<u64> = key.clone();

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_some());
    assert!(clone.public_key().is_some());
    assert!(clone.private_key().is_some());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

#[test]
fn test_init_only_public_64() {
    let key: AsymmetricKey<u64> = AsymmetricKey::only_public(&SAMPLE_PUBLIC_64);

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_none());
    assert!(key.public_key().unwrap() == SAMPLE_PUBLIC_64);

    drop(key);
}

#[test]
fn test_clone_only_public_64() {
    let key: AsymmetricKey<u64> = AsymmetricKey::only_public(&SAMPLE_PUBLIC_64);
    let clone: AsymmetricKey<u64> = key.clone();

    assert!(key.public_key().is_some());
    assert!(key.private_key().is_none());
    assert!(clone.public_key().is_some());
    assert!(clone.private_key().is_none());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

#[test]
fn test_init_only_private_64() {
    let key: AsymmetricKey<u64> = AsymmetricKey::only_private(&SAMPLE_PRIVATE_64);

    assert!(key.public_key().is_none());
    assert!(key.private_key().is_some());
    assert!(key.private_key().unwrap() == SAMPLE_PRIVATE_64);

    drop(key);
}

#[test]
fn test_clone_only_private_64() {
    let key: AsymmetricKey<u32> = AsymmetricKey::only_private(&SAMPLE_PRIVATE_32);
    let clone: AsymmetricKey<u32> = key.clone();

    assert!(key.public_key().is_none());
    assert!(key.private_key().is_some());
    assert!(clone.public_key().is_none());
    assert!(clone.private_key().is_some());
    assert_eq!(key.public_key(), clone.public_key());
    assert_eq!(key.private_key(), clone.private_key());

    drop(key);
    drop(clone);
}

/// Key Inequality

#[test]
fn test_key_inequality_8() {
    let key1: AsymmetricKey<u8> = AsymmetricKey::new(&SAMPLE_PUBLIC_8_1, &SAMPLE_PRIVATE_8_1);
    let key2: AsymmetricKey<u8> = AsymmetricKey::new(&SAMPLE_PUBLIC_8_2, &SAMPLE_PRIVATE_8_2);

    assert!(key1 != key2);
}

#[test]
fn test_key_inequality_16() {
    let key1: AsymmetricKey<u16> = AsymmetricKey::new(&SAMPLE_PUBLIC_16_1, &SAMPLE_PRIVATE_16_1);
    let key2: AsymmetricKey<u16> = AsymmetricKey::new(&SAMPLE_PUBLIC_16_2, &SAMPLE_PRIVATE_16_2);

    assert!(key1 != key2);
}

#[test]
fn test_key_inequality_32() {
    let key1: AsymmetricKey<u32> = AsymmetricKey::new(&SAMPLE_PUBLIC_32_1, &SAMPLE_PRIVATE_32_1);
    let key2: AsymmetricKey<u32> = AsymmetricKey::new(&SAMPLE_PUBLIC_32_2, &SAMPLE_PRIVATE_32_2);

    assert!(key1 != key2);
}

#[test]
fn test_key_inequality_64() {
    let key1: AsymmetricKey<u64> = AsymmetricKey::new(&SAMPLE_PUBLIC_64_1, &SAMPLE_PRIVATE_64_1);
    let key2: AsymmetricKey<u64> = AsymmetricKey::new(&SAMPLE_PUBLIC_64_2, &SAMPLE_PRIVATE_64_2);

    assert!(key1 != key2);
}
