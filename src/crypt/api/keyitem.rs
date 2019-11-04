
use std::{
    alloc::{
        alloc,
        dealloc,
        Layout
    },
    marker::PhantomData,
    mem,
    ops::Deref,
    ptr
};

use rand::{
    thread_rng,
    Rng
};

pub trait KeyType {
    type ValueType: Sized + PartialEq + Copy;
}

impl KeyType for u8 {
    type ValueType = u8;
}

impl KeyType for u16 {
    type ValueType = u16;
}

impl KeyType for u32 {
    type ValueType = u32;
}

impl KeyType for u64 {
    type ValueType = u64;
}

impl KeyType for u128 {
    type ValueType = u128;
}

pub struct KeyItem<T: KeyType> {
    data: *mut T::ValueType,
    size: usize,
    _phantom: PhantomData<T>
}

impl<T: KeyType> KeyItem<T> {
    pub fn new(data: &[T::ValueType]) -> Self {
        unsafe {
            let mut res = Self::default();
            let ptr: *mut T::ValueType = alloc(Self::make_layout(data.len() * mem::size_of::<T::ValueType>())) as *mut T::ValueType;
            if ptr.is_null() {
                panic!("could not allocate enough memory for key item");
            }
            res.data = ptr;
            res.size = data.len();
            ptr::copy(data.as_ptr(), res.data, data.len());
            res
        }
    }
    pub fn data(&self) -> Option<&[T::ValueType]> {
        if self.data.is_null() {
            return None;
        }
        return Some(self.deref());
    }
    pub fn size(&self) -> usize {
        self.size
    }
    pub unsafe fn as_ptr(&self) -> *const T::ValueType {
        self.data
    }
    fn make_layout(cap: usize) -> Layout {
        unsafe { Layout::from_size_align_unchecked(cap, mem::align_of::<T>()) }
    }
}

impl<T: KeyType> Default for KeyItem<T> {
    fn default() -> Self {
        Self {
            data: ptr::null_mut::<T::ValueType>(),
            size: 0,
            _phantom: PhantomData{}
        }
    }
}

impl<T: KeyType> Clone for KeyItem<T> {
    fn clone(&self) -> Self {
        if self.data.is_null() {
            return Self::default()
        }
        return Self::new(self.deref())
    }
}

impl<T: KeyType> Deref for KeyItem<T> {
    type Target = [T::ValueType];
    fn deref(&self) -> &Self::Target {
        if self.data.is_null() {
            return &[];
        }
        unsafe {
            return ::std::slice::from_raw_parts::<T::ValueType>(self.data, self.size);
        }
    }
}

impl<T: KeyType> PartialEq<Self> for KeyItem<T> {
    fn eq(&self, rhs: &Self) -> bool {
        if self.data.is_null() || rhs.data.is_null() {
            return false;
        }
        if self.data == rhs.data {
            return true;
        }
        self.data() != None && rhs.data() != None && self.data() == rhs.data()
    }
}

impl<T: KeyType> Drop for KeyItem<T> {
    fn drop(&mut self) {
        unsafe {
            if self.size > 0 {
                let num_bytes = self.size * mem::size_of::<T::ValueType>();
                // zeroes the memory
                ptr::write_bytes::<T::ValueType>(self.data, 0, self.size);
                // then deallocate
                dealloc(
                    self.data as *mut u8,
                    Self::make_layout(num_bytes)
                );
            }
        }
    }
}

pub trait KeyTrait<T: KeyType> {
    fn key(&self) -> Option<&[T::ValueType]> { None }
}

pub trait AsymmetricKeyTrait<T: KeyType>: KeyTrait<T> {
}

pub trait PublicAsymmetricKeyTrait<T: KeyType>: AsymmetricKeyTrait<T> {
    fn public_key(&self) -> Option<&[T::ValueType]>;
}

pub trait PrivateAsymmetricKeyTrait<T: KeyType>: AsymmetricKeyTrait<T> {
    fn private_key(&self) -> Option<&[T::ValueType]>;
}

pub trait SymmetricKeyTrait<T: KeyType>: KeyTrait<T> {
    fn iv(&self) -> Option<&[T::ValueType]>;
    fn salt(&self) -> Option<&[T::ValueType]>;
}

#[derive(Clone, Default, PartialEq)]
pub struct Key<T: KeyType> (KeyItem<T>);

impl<T: KeyType> Key<T> {
    pub fn new(_key: &[T::ValueType]) -> Self {
        Self (KeyItem::new(_key))
    }
}

impl<T> KeyTrait<T> for Key<T> where T: KeyType {
    fn key(&self) -> Option<&[T::ValueType]> {
        self.0.data()
    }
}

#[derive(Clone, Default, PartialEq)]
pub struct AsymmetricKey<T: KeyType> (KeyItem<T>, KeyItem<T>);

impl<T: KeyType> AsymmetricKey<T> {
    pub fn new(_public: &[T::ValueType], _private: &[T::ValueType]) -> Self {
        Self (
            KeyItem::new(_public),
            KeyItem::new(_private)
        )
    }
    pub fn only_public(_key: &[T::ValueType]) -> Self {
        Self (
            KeyItem::new(_key),
            KeyItem::default()
        )
    }
    pub fn only_private(_key: &[T::ValueType]) -> Self {
        Self (
            KeyItem::default(),
            KeyItem::new(_key)
        )
    }
}

impl<T> KeyTrait<T> for AsymmetricKey<T> where T: KeyType {
}

impl<T> AsymmetricKeyTrait<T> for AsymmetricKey<T> where T: KeyType {
}

impl<T: KeyType> PublicAsymmetricKeyTrait<T> for AsymmetricKey<T> {
    fn public_key(&self) -> Option<&[T::ValueType]> {
        self.0.data()
    }
}

impl<T: KeyType> PrivateAsymmetricKeyTrait<T> for AsymmetricKey<T> {
    fn private_key(&self) -> Option<&[T::ValueType]> {
        self.1.data()
    }
}

#[derive(Clone, Default, PartialEq)]
pub struct SymmetricKey<T: KeyType> (KeyItem<T>, KeyItem<T>, KeyItem<T>);

impl<'a, T: KeyType> SymmetricKey<T> {
    pub fn new(_key: &[T::ValueType], _iv: &[T::ValueType], _salt: &[T::ValueType]) -> Self {
        Self (
            KeyItem::new(_key),
            KeyItem::new(_iv),
            KeyItem::new(_salt)
        )
    }
    pub fn with_key(_key: &[T::ValueType]) -> Self {
        Self (
            KeyItem::new(_key),
            KeyItem::default(),
            KeyItem::default()
        )
    }
    pub fn and_iv(&mut self, _iv: &[T::ValueType]) -> &mut Self {
        self.1 = KeyItem::new(_iv);
        self
    }
    pub fn and_salt(&mut self, _salt: &[T::ValueType]) -> &mut Self {
        self.2 = KeyItem::new(_salt);
        self
    }
    pub fn and_auto_iv(&mut self, _len: usize) -> &mut Self {
        let generated: Box<[T::ValueType]> = self.generate(_len);
        self.and_iv(generated.deref())
    }
    pub fn and_auto_salt(&mut self, _len: usize) -> &mut Self {
        let generated: Box<[T::ValueType]> = self.generate(_len);
        self.and_salt(generated.deref())
    }
    fn generate(&self, _len: usize) -> Box<[<T as KeyType>::ValueType]> {
        let mut v: Vec<T::ValueType> = Vec::with_capacity(_len);
        if _len > 0 {
            let mut rng = thread_rng();

            let element_size = mem::size_of::<T::ValueType>();

            const CHARSET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                abcdefghijklmnopqrstuvwxyz\
                0123456789)(*&^%$#@!~";

            for _ in 0.._len {
                let mut vtev: Vec<u8> = Vec::with_capacity(element_size);
                for _ in 0..element_size {
                    let idx = rng.gen_range(0, CHARSET.len());
                    let chr = CHARSET[idx];
                    vtev.push(chr);
                }
                unsafe {
                    v.push(
                        ptr::read_unaligned(
                            mem::transmute::<*const u8, *const T::ValueType>(
                                vtev.as_ptr()
                            )
                        )
                    );
                }
            }
        }
        std::boxed::Box::<[T::ValueType]>::from(v.as_slice())
    }
}

impl<T> KeyTrait<T> for SymmetricKey<T> where T: KeyType {
    fn key(&self) -> Option<&[T::ValueType]> {
        self.0.data()
    }
}

impl<T> SymmetricKeyTrait<T> for SymmetricKey<T> where T: KeyType {
    fn iv(&self) -> Option<&[T::ValueType]> {
        self.1.data()
    }
    fn salt(&self) -> Option<&[T::ValueType]> {
        self.2.data()
    }
}
