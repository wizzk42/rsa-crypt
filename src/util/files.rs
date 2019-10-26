///
///
///

use std::{
    fs::File,
    io::prelude::*,
    path::Path,
};

pub fn read_from_file(name: &str) -> Vec<u8> {
    let mut result: Vec<u8> = vec![];

    let path = Path::new(name);
    let file = File::open(&path);

    if let Ok(mut file_handle) = file {
        file_handle
            .read_to_end(&mut result)
            .unwrap_or_else(|_| {
                result.clear();
                0
            }
        );
    }
    result
}
