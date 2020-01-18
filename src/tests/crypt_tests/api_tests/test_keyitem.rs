///
///
///

#[cfg(test)]
extern crate rsa_crypt;

#[cfg(test)]
use rsa_crypt::KeyItem;

#[rustfmt::skip]
const SAMPLE_DATA_8: [u8;4] = [0,2^7,2^7+1,2^8-1];
#[rustfmt::skip]
const SAMPLE_DATA_16: [u16;4] = [2^8+1,2^8+2,2^8+3,2^16-1];
#[rustfmt::skip]
const SAMPLE_DATA_32: [u32;4] = [2^16+1,2^16+2,2^16+3,2^32-1];
#[rustfmt::skip]
const SAMPLE_DATA_64: [u64;4] = [2^32+1,2^32+2,2^32+3,2^64-1];
#[rustfmt::skip]
const SAMPLE_DATA_64_1: [u64;4] = [2^32+16,2^32+32,2^32+48,2^64-1];
#[rustfmt::skip]
const SAMPLE_DATA_64_2: [u64;5] = [2^64-16,2^64-32,2^64+48,2^64+64,2^64-1];

#[test]
fn test_init_8() {
    let keyitem: KeyItem<u8> = KeyItem::new(&SAMPLE_DATA_8);

    assert!(keyitem.data().is_some());
    assert_eq!(keyitem.data().unwrap(), &SAMPLE_DATA_8);
    unsafe {
        assert!(!keyitem.as_ptr().is_null());
    }
    assert_eq!(keyitem.size(), SAMPLE_DATA_8.len());

    drop(keyitem);
}

#[test]
fn test_clone_8() {
    let keyitem: KeyItem<u8> = KeyItem::new(&SAMPLE_DATA_8);
    let clone: KeyItem<u8> = keyitem.clone();
    assert!(keyitem == clone);
    unsafe {
        assert!(keyitem.as_ptr() != clone.as_ptr());
    }
}

#[test]
fn test_init_default_8() {
    let keyitem: KeyItem<u8> = KeyItem::default();

    assert!(keyitem.data().is_none());
    unsafe {
        assert!(keyitem.as_ptr().is_null());
    }
    assert_eq!(keyitem.size(), 0);

    drop(keyitem);
}

#[test]
fn test_init_16() {
    let keyitem: KeyItem<u16> = KeyItem::new(&SAMPLE_DATA_16);

    assert!(keyitem.data().is_some());
    assert_eq!(keyitem.data().unwrap(), &SAMPLE_DATA_16);
    unsafe {
        assert!(!keyitem.as_ptr().is_null());
    }
    assert_eq!(keyitem.size(), SAMPLE_DATA_16.len());

    drop(keyitem);
}

#[test]
fn test_clone_16() {
    let keyitem: KeyItem<u16> = KeyItem::new(&SAMPLE_DATA_16);
    let clone: KeyItem<u16> = keyitem.clone();
    assert!(keyitem == clone);
    unsafe {
        assert!(keyitem.as_ptr() != clone.as_ptr());
    }
}

#[test]
fn test_init_default_16() {
    let keyitem: KeyItem<u16> = KeyItem::default();

    assert!(keyitem.data().is_none());
    unsafe {
        assert!(keyitem.as_ptr().is_null());
    }
    assert_eq!(keyitem.size(), 0);

    drop(keyitem);
}

#[test]
fn test_init_32() {
    let keyitem: KeyItem<u32> = KeyItem::new(&SAMPLE_DATA_32);

    assert!(keyitem.data().is_some());
    assert_eq!(keyitem.data().unwrap(), &SAMPLE_DATA_32);
    unsafe {
        assert!(!keyitem.as_ptr().is_null());
    }
    assert_eq!(keyitem.size(), SAMPLE_DATA_32.len());

    drop(keyitem);
}

#[test]
fn test_clone_32() {
    let keyitem: KeyItem<u32> = KeyItem::new(&SAMPLE_DATA_32);
    let clone: KeyItem<u32> = keyitem.clone();
    assert!(keyitem == clone);
    unsafe {
        assert!(keyitem.as_ptr() != clone.as_ptr());
    }
}

#[test]
fn test_init_default_32() {
    let keyitem: KeyItem<u32> = KeyItem::default();

    assert!(keyitem.data().is_none());
    unsafe {
        assert!(keyitem.as_ptr().is_null());
    }
    assert_eq!(keyitem.size(), 0);

    drop(keyitem);
}

#[test]
fn test_init_64() {
    let keyitem: KeyItem<u64> = KeyItem::new(&SAMPLE_DATA_64);

    assert!(keyitem.data().is_some());
    assert_eq!(keyitem.data().unwrap(), &SAMPLE_DATA_64);
    unsafe {
        assert!(!keyitem.as_ptr().is_null());
    }
    assert_eq!(keyitem.size(), SAMPLE_DATA_64.len());

    drop(keyitem);
}

#[test]
fn test_clone_64() {
    let keyitem: KeyItem<u64> = KeyItem::new(&SAMPLE_DATA_64);
    let clone: KeyItem<u64> = keyitem.clone();
    assert!(keyitem == clone);
    unsafe {
        assert!(keyitem.as_ptr() != clone.as_ptr());
    }
}

#[test]
fn test_init_default_64() {
    let keyitem: KeyItem<u64> = KeyItem::default();

    assert!(keyitem.data().is_none());
    unsafe {
        assert!(keyitem.as_ptr().is_null());
    }
    assert_eq!(keyitem.size(), 0);

    drop(keyitem);
}

#[test]
fn test_s_not_eq() {
    let keyitem1: KeyItem<u64> = KeyItem::new(&SAMPLE_DATA_64_1);
    let keyitem2: KeyItem<u64> = KeyItem::new(&SAMPLE_DATA_64_2);

    assert!(keyitem1 != keyitem2);
    unsafe {
        assert!(keyitem1.as_ptr() != keyitem2.as_ptr());
    }

    drop(keyitem1);
    drop(keyitem2);
}
