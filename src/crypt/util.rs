///
///
///

pub fn load_aes_key(_data: &[u8]) -> (Vec<u8>,  Vec<u8>, Vec<u8>) {
    let mut key: Vec<u8> = vec![];
    let mut iv: Vec<u8> = vec![];
    let mut salt: Vec<u8> = vec![];

    for line in _data.split(|c| *c as char == '\n') {
        let k: &str = std::str::from_utf8(
            line.splitn(2, |c| *c as char == '=')
                .next()
                .unwrap()
        ).unwrap();
        let v: &str = std::str::from_utf8(
            line.splitn(2, |c| *c as char == '=')
                .last()
                .unwrap()
        ).unwrap();
        match k.trim() {
            "key" => {
                key = v.as_bytes().to_vec();
            }
            "iv" => {
                iv = v.as_bytes().to_vec();
            }
            "salt" => {
                salt = v.as_bytes().to_vec();
            }
            _ => {
                // skip other keys
            }
        }
    }
    (key, iv, salt)
}

pub fn load_rsa_key(_data: &[u8]) -> Vec<u8> {
    _data.to_vec()
}
