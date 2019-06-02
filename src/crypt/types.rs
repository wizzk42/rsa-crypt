///
///
///

pub use std::{
    cell::RefCell,
    rc::Rc,
};

pub type ByteVec = Vec<u8>;
pub type ByteVecRef = RefCell<ByteVec>;
pub type ByteVecSharedPtr = Rc<ByteVecRef>;

pub fn new_mut_byte_vec(_v: ByteVec) -> ByteVecSharedPtr {
    Rc::new(RefCell::new(_v))
}
