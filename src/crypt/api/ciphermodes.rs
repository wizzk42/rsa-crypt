///
///
///

#[derive(Clone, Debug)]
pub enum CipherBlockMode {
    Cbc,
    Ccm,
    Cfb,
    Ctr,
    Gcm,
    Ofb,
    Xts,
}
