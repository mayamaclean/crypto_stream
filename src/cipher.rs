use rust_sodium::crypto::stream;

#[derive(Clone)]
pub enum MultiKey {
    Salsa(stream::salsa20::Key),
    ChaCha(stream::chacha20::Key),
    XSalsa(stream::xsalsa20::Key),
    XChaCha(stream::xchacha20::Key),
}

#[derive(Copy, Clone)]
pub enum MultiNonce {
    Salsa(stream::salsa20::Nonce),
    ChaCha(stream::chacha20::Nonce),
    XSalsa(stream::xsalsa20::Nonce),
    XChaCha(stream::xchacha20::Nonce),
}

pub trait Cipher: Clone + Send + Sync + 'static {
    fn mut_crypt(&self, data: &mut [u8], k: &MultiKey, n: &MultiNonce, ic: u64) -> Result<(),()>;
}

#[derive(Copy, Clone)]
pub struct Salsa();

impl Cipher for Salsa {
    fn mut_crypt(&self, data: &mut [u8], k: &MultiKey, n: &MultiNonce, ic: u64) -> Result<(),()> {
        let key;
        match k {
            MultiKey::Salsa(x) => key = x,
            _ => return Err(()),
        }

        let nonce;
        match n {
            MultiNonce::Salsa(x) => nonce = x,
            _ => return Err(()),
        }

        stream::salsa20::stream_xor_ic_inplace(data, nonce, ic, key);
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct ChaCha();

impl Cipher for ChaCha {
    fn mut_crypt(&self, data: &mut [u8], k: &MultiKey, n: &MultiNonce, ic: u64) -> Result<(),()> {
        let key;
        match k {
            MultiKey::ChaCha(x) => key = x,
            _ => return Err(()),
        }

        let nonce;
        match n {
            MultiNonce::ChaCha(x) => nonce = x,
            _ => return Err(()),
        }

        stream::chacha20::stream_xor_ic_inplace(data, nonce, ic, key);
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct XSalsa();

impl Cipher for XSalsa {
    fn mut_crypt(&self, data: &mut [u8], k: &MultiKey, n: &MultiNonce, ic: u64) -> Result<(),()> {
        let key;
        match k {
            MultiKey::XSalsa(x) => key = x,
            _ => return Err(()),
        }

        let nonce;
        match n {
            MultiNonce::XSalsa(x) => nonce = x,
            _ => return Err(()),
        }

        stream::xsalsa20::stream_xor_ic_inplace(data, nonce, ic, key);
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct XChaCha();

impl Cipher for XChaCha {
    fn mut_crypt(&self, data: &mut [u8], k: &MultiKey, n: &MultiNonce, ic: u64) -> Result<(),()> {
        let key;
        match k {
            MultiKey::XChaCha(x) => key = x,
            _ => return Err(()),
        }

        let nonce;
        match n {
            MultiNonce::XChaCha(x) => nonce = x,
            _ => return Err(()),
        }

        stream::xchacha20::stream_xor_ic_inplace(data, nonce, ic, key);
        Ok(())
    }
}
