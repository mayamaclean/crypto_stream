use ordered_stream::OrderedStream;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}, Mutex};
use std::thread;
use std::time::Duration;

use crate::{hmac::*};

pub struct AsyncTag<H: Hmac> {
    incoming: Arc<Mutex<OrderedStream<u8>>>,
    salt: Arc<KeySalt>,
    ready: Arc<AtomicBool>,
    hmac: Arc<Mutex<Vec<u8>>>,
    func: H,
}

impl<H: Hmac> AsyncTag<H> {
    pub fn new(i: OrderedStream<u8>, ks: KeySalt) -> AsyncTag<H> {
        let h: H = unsafe { std::mem::uninitialized() };

        AsyncTag {
            incoming: Arc::new(Mutex::new(i)),
            salt: Arc::new(ks),
            ready: Arc::new(AtomicBool::new(false)),
            hmac: Arc::new(Mutex::new(Vec::with_capacity(64))),
            func: h,
        }
    }

    pub fn set_salt(&mut self, ks: KeySalt) {
        self.salt = Arc::new(ks);
    }

    pub fn calculate_async(&self, d: Duration) {
        let salt = Arc::clone(&self.salt);
        let h = self.func.clone();
        let incoming = Arc::clone(&self.incoming);
        let red = Arc::clone(&self.ready);
        let hmac = Arc::clone(&self.hmac);
        let func = self.func.clone();

        thread::spawn(move || {
            match func.hmac_type() {
                HmacType::Poly1305(_) => { },
                _ => {
                    let mut lock = incoming.lock().expect("could not acquire stream lock");
                    let tags = lock.iter_mut_timeout(d).collect();
                    let tag = h.tree_hash(tags, &*salt).expect("hmac/key mismatch");

                    let mut l = hmac.lock().expect("could not lock hmac field");
                    l.extend_from_slice(&tag);
                    red.store(true, Ordering::Relaxed);
                }
            }
        });
    }

    pub fn calculate(&self, d: Duration) {
        match self.func.hmac_type() {
            HmacType::Poly1305(_) => { },
            _ => {
                let tags = self.collect_tags(d);
                let tag = self.func.tree_hash(tags, &*self.salt).expect("hmac/key mismatch");
                let mut hmac = self.hmac.lock().expect("could not lock hmac field");
                hmac.extend_from_slice(&tag);
                self.ready.store(true, Ordering::Relaxed);
            },
        }
    }

    pub fn is_ready(&self) -> Result<Vec<u8>, ()> {
        let tag = Arc::clone(&self.hmac);
        match tag.try_lock() {
            Ok(lock) => {
                if self.ready.load(Ordering::Relaxed) {
                    return Ok((*lock).to_owned())
                }
            },
            Err(_) => return Err(())
        }
        Err(())
    }

    pub fn collect_tags(&self, timeout: Duration) -> Vec<Vec<u8>> {
        let mut lock = self.incoming.lock().expect("could not acquire stream lock");
        lock.iter_mut_timeout(timeout).collect()
    }

    pub fn wait(&self) -> Vec<u8> {
        loop {
            if let Ok(tag) = self.is_ready() {
                return tag
            }
        }
    }
}
