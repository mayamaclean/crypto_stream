use blake2_rfc::blake2b::Blake2b as Blake;
use rust_sodium::{crypto::onetimeauth::poly1305, crypto::stream::chacha20, utils::memzero};
use std::sync::Arc;
use tiny_keccak::Keccak;

pub enum HmacType {
    Poly1305(Poly1305),
    Blake2b(Blake2b),
    Sha3224(Sha3224),
    Sha3256(Sha3256),
    Sha3384(Sha3384),
    Sha3512(Sha3512),
}

#[derive(Clone)]
pub enum KeySalt {
    Poly1305(PolyKey),
    Salt(Vec<u8>),
}

#[derive(Clone)]
pub struct PolyKey {
    key: Arc<chacha20::Key>,
    non: Arc<chacha20::Nonce>,
    tags: Arc<Option<Vec<Vec<u8>>>>,
}

#[derive(Copy, Clone)]
pub struct Poly1305();

#[derive(Copy, Clone)]
pub struct Blake2b();

#[derive(Copy, Clone)]
pub struct Sha3224();

#[derive(Copy, Clone)]
pub struct Sha3256();

#[derive(Copy, Clone)]
pub struct Sha3384();

#[derive(Copy, Clone)]
pub struct Sha3512();

pub trait Hmac: Clone + Send + Sync + 'static {
    fn tag(&self, data: &[u8], ks: &KeySalt, idx: u64) -> Result<Vec<u8>,()>;
    fn tree_hash(&self, tags: Vec<Vec<u8>>, ks: &KeySalt) -> Result<Vec<u8>,()>;
    fn hmac_type(&self) -> HmacType;
}

// maybe use a speck key schedule?
impl PolyKey {
    pub fn new(k: chacha20::Key, n: chacha20::Nonce, t: Option<Vec<Vec<u8>>>) -> Self {
        Self {
            key: Arc::new(k),
            non: Arc::new(n),
            tags: Arc::new(t),
        }
    }

    pub fn get_key(&self, idx: u64) -> poly1305::Key {
        let mut k = [0u8; 32];
        chacha20::stream_xor_ic_inplace(&mut k, &*self.non, idx, &*self.key);

        let key = poly1305::Key::from_slice(&k).unwrap();
        memzero(&mut k);

        key
    }

    pub fn is_authenticator(&self) -> bool {
        self.tags.is_some()
    }

    pub fn get_tag(&self, idx: u64) -> Option<poly1305::Tag> {
        if !self.is_authenticator() {
            return None
        }

        let t = self.tags.iter().nth(0).unwrap().iter().nth(idx as usize).unwrap();

        Some(poly1305::Tag::from_slice(&t).expect("invalid poly1305 tag"))
    }

    pub fn verify(tags: Vec<Vec<u8>>) -> bool {
        for check in tags {
            if check[0] == 0 {
                return false
            }
        }
        true
    }
}

impl Hmac for Poly1305 {
    fn tag(&self, data: &[u8], ks: &KeySalt, idx: u64) -> Result<Vec<u8>,()>{
        let k;
        match ks {
            KeySalt::Poly1305(x) => k = x,
            _ => return Err(()),
        }
        let key = k.get_key(idx);

        if k.is_authenticator() {
            let tag = k.get_tag(idx).unwrap();
            let verified = poly1305::verify(&tag, data, &key);

            Ok(vec![verified as u8])
        } else {
            let tag = poly1305::authenticate(data, &key);

            Ok(tag[..].to_vec())
        }
    }

    fn tree_hash(&self, tags: Vec<Vec<u8>>, ks: &KeySalt) -> Result<Vec<u8>,()> {
        Err(())
    }

    fn hmac_type(&self) -> HmacType {
        HmacType::Poly1305(*self)
    }
}

impl Hmac for Blake2b {
    fn tag(&self, data: &[u8], ks: &KeySalt, idx: u64) -> Result<Vec<u8>,()> {
        let salt;
        match ks {
            KeySalt::Salt(x) => salt = x,
            _ => return Err(()),
        }

        let mut b2b = Blake::with_key(64, &salt);
        b2b.update(data);

        Ok(b2b.finalize().as_bytes().to_vec())
    }

    fn tree_hash(&self, tags: Vec<Vec<u8>>, ks: &KeySalt) -> Result<Vec<u8>,()> {
        let salt;
        match ks {
            KeySalt::Salt(x) => salt = x,
            _ => return Err(()),
        }

        let mut b2b = Blake::with_key(64, &salt);

        for tag in tags {
            b2b.update(&tag);
        }

        Ok(b2b.finalize().as_bytes().to_vec())
    }

    fn hmac_type(&self) -> HmacType {
        HmacType::Blake2b(*self)
    }
}

impl Hmac for Sha3224 {
    fn tag(&self, data: &[u8], ks: &KeySalt, idx: u64) -> Result<Vec<u8>,()> {
        let salt;
        match ks {
            KeySalt::Salt(x) => salt = x,
            _ => return Err(()),
        }

        let mut sha = Keccak::new_sha3_224();
        sha.update(&salt);
        sha.update(data);

        let mut tag = vec![0u8; 28];
        sha.finalize(&mut tag);

        Ok(tag)
    }

    fn tree_hash(&self, tags: Vec<Vec<u8>>, ks: &KeySalt) -> Result<Vec<u8>,()> {
        let salt;
        match ks {
            KeySalt::Salt(x) => salt = x,
            _ => return Err(()),
        }

        let mut tag = vec![0u8; 28];
        let mut sha = Keccak::new_sha3_224();
        sha.update(salt);

        for tag in tags {
            sha.update(&tag);
        }

        sha.finalize(&mut tag);
        Ok(tag)
    }

    fn hmac_type(&self) -> HmacType {
        HmacType::Sha3224(*self)
    }
}

impl Hmac for Sha3256 {
    fn tag(&self, data: &[u8], ks: &KeySalt, idx: u64) -> Result<Vec<u8>,()> {
        let salt;
        match ks {
            KeySalt::Salt(x) => salt = x,
            _ => return Err(()),
        }

        let mut sha = Keccak::new_sha3_256();
        sha.update(&salt);
        sha.update(data);

        let mut tag = vec![0u8; 32];
        sha.finalize(&mut tag);

        Ok(tag)
    }

    fn tree_hash(&self, tags: Vec<Vec<u8>>, ks: &KeySalt) -> Result<Vec<u8>,()> {
        let salt;
        match ks {
            KeySalt::Salt(x) => salt = x,
            _ => return Err(()),
        }

        let mut buf = vec![0u8; 32];
        let mut sha = Keccak::new_sha3_256();
        sha.update(salt);

        for tag in tags {
            sha.update(&tag);
        }

        sha.finalize(&mut buf);
        Ok(buf)
    }

    fn hmac_type(&self) -> HmacType {
        HmacType::Sha3256(*self)
    }
}

impl Hmac for Sha3384 {
    fn tag(&self, data: &[u8], ks: &KeySalt, idx: u64) -> Result<Vec<u8>,()> {
        let salt;
        match ks {
            KeySalt::Salt(x) => salt = x,
            _ => return Err(()),
        }

        let mut sha = Keccak::new_sha3_384();
        sha.update(&salt);
        sha.update(data);

        let mut tag = vec![0u8; 48];
        sha.finalize(&mut tag);

        Ok(tag)
    }

    fn tree_hash(&self, tags: Vec<Vec<u8>>, ks: &KeySalt) -> Result<Vec<u8>,()> {
        let salt;
        match ks {
            KeySalt::Salt(x) => salt = x,
            _ => return Err(()),
        }

        let mut tag = vec![0u8; 48];
        let mut sha = Keccak::new_sha3_224();
        sha.update(salt);

        for tag in tags {
            sha.update(&tag);
        }

        sha.finalize(&mut tag);
        Ok(tag)
    }

    fn hmac_type(&self) -> HmacType {
        HmacType::Sha3384(*self)
    }
}

impl Hmac for Sha3512 {
    fn tag(&self, data: &[u8], ks: &KeySalt, idx: u64) -> Result<Vec<u8>,()> {
        let salt;
        match ks {
            KeySalt::Salt(x) => salt = x,
            _ => return Err(()),
        }

        let mut sha = Keccak::new_sha3_384();
        sha.update(&salt);
        sha.update(data);

        let mut tag = vec![0u8; 64];
        sha.finalize(&mut tag);

        Ok(tag)
    }

    fn tree_hash(&self, tags: Vec<Vec<u8>>, ks: &KeySalt) -> Result<Vec<u8>,()> {
        let salt;
        match ks {
            KeySalt::Salt(x) => salt = x,
            _ => return Err(()),
        }

        let mut tag = vec![0u8; 64];
        let mut sha = Keccak::new_sha3_224();
        sha.update(salt);

        for tag in tags {
            sha.update(&tag);
        }

        sha.finalize(&mut tag);
        Ok(tag)
    }

    fn hmac_type(&self) -> HmacType {
        HmacType::Sha3512(*self)
    }
}
