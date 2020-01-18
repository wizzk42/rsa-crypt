///
///
///
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct HexVec(Vec<u8>);

impl HexVec {
    pub fn from_hex(_s: &str) -> Self {
        HexVec(hex::decode(_s).unwrap())
    }
    pub fn from_bytes(_b: Vec<u8>) -> Self {
        HexVec(_b)
    }
    pub fn empty() -> Self {
        HexVec(vec![])
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.clone())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl FromStr for HexVec {
    type Err = ();

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Ok(HexVec::from_hex(_s))
    }
}
