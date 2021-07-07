///
///
///
use std::str::FromStr;

#[derive(Clone, Debug)]
pub enum Algorithm {
    None,
    Aes,
    Rsa,
}

impl FromStr for Algorithm {
    type Err = ();

    fn from_str(_s: &str) -> Result<Algorithm, ()> {
        match _s {
            "aes" => Ok(Algorithm::Aes),
            "rsa" => Ok(Algorithm::Rsa),
            _ => Ok(Algorithm::None),
        }
    }
}
