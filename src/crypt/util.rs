///
///
///

pub fn load_aes_key(_data: &[u8]) -> (&str, &str, &str) {
    let mut key: &str = "";
    let mut iv: &str = "";
    let mut salt: &str = "";

    for line in _data.split(|c| *c as char == '\n') {
        let k: &str = std::str::from_utf8(
            line.splitn(2, |c| *c as char == '=')
                .next()
                .unwrap()
        ).unwrap();
        let v: &str = std::str::from_utf8(
            line.splitn(2, |c| *c as char == '=')
                .next()
                .unwrap()
        ).unwrap();
        match k.trim() {
            "key" => {
                key = v;
            }
            "iv" => {
                iv = v;
            }
            "salt" => {
                salt = v;
            }
            _ => {
                // skip other keys
            }
        }
    }
    (key, iv, salt)
}
