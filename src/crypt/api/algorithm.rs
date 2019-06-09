///
///
///

use std::str::FromStr;

#[derive(Clone, Debug)]
pub enum Algorithm {
    Aes,
    Rsa,
}

impl FromStr for Algorithm {
    type Err = ();

    fn from_str(_s: &str) -> Result<Algorithm, ()> {
        return match _s {
            "aes" => Ok(Algorithm::Aes),
            "rsa" => Ok(Algorithm::Rsa),
            _ => Err(()),
        };
    }
}
