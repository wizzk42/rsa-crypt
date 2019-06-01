///
///
///

use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct HexData(Vec<u8>);

impl HexData {
    pub fn from_hex(_s: &str) -> Self {
        HexData(hex::decode(_s).unwrap())
    }
    pub fn from_bytes(_b : Vec<u8>) -> Self {
        HexData(_b)
    }
    pub fn empty() -> Self {
        HexData(vec![])
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.clone())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl FromStr for HexData {
    type Err = ();

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Ok(HexData::from_hex(_s))
    }
}
