use std::fmt::{self, Debug};
use crossbeam_channel::{Sender, unbounded, RecvError, RecvTimeoutError};
use ordered_stream::OrderedStream;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::io::{self, ErrorKind, Read, Write};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}, Mutex, RwLock};
use std::time::Duration;

use crate::{async_tag::*, cipher::*, hmac::*};

pub fn crypto_stream<C: Cipher>(k: MultiKey, n: MultiNonce, threads: usize) -> (CryptoStreamW<C>, CryptoStreamR) {
    let (crypt_tx, crypt_rx) = unbounded::<(u64, Vec<u8>)>();

    let c_stream = OrderedStream::with_recvr(crypt_rx);

    let w_cnt = Arc::new(AtomicUsize::new(1));
    let len = Arc::new(AtomicUsize::new(0));
    let pending = Arc::new(AtomicUsize::new(0));
    let buffer = Arc::new(AtomicUsize::new(0));

    let reader = CryptoStreamR {
        output: Arc::new(RwLock::new(c_stream)),
        w_cnt: Arc::clone(&w_cnt),
        len: Arc::clone(&len),
        pending: Arc::clone(&pending),
        buffer,
    };

    let pool = ThreadPoolBuilder::new().num_threads(threads).breadth_first().build().unwrap();

    let c: C = unsafe { std::mem::uninitialized() };

    let writer = CryptoStreamW {
        k: Arc::new(k),
        n: Arc::new(n),
        idx: 0,
        ic: 0,
        c,
        crypt_tx,
        pool: Arc::new(pool),
        errors: Arc::new(Mutex::new(Vec::new())),
        w_cnt,
        len,
        pending,
    };

    (writer, reader)
}

pub fn hmac_stream<H: Hmac>(ks: KeySalt, threads: usize) -> (HmacStreamW<H>, HmacStreamR<H>) {
    let (data_tx, data_rx) = unbounded::<(u64, Vec<u8>)>();
    let (tag_tx, tag_rx) = unbounded::<(u64, Vec<u8>)>();

    let data_stream = OrderedStream::with_recvr(data_rx);
    let tag_stream = OrderedStream::with_recvr(tag_rx);

    let tag = AsyncTag::new(tag_stream, ks.clone());

    let w_cnt = Arc::new(AtomicUsize::new(1));
    let len = Arc::new(AtomicUsize::new(0));
    let pending = Arc::new(AtomicUsize::new(0));
    let buffer = Arc::new(AtomicUsize::new(0));

    let reader = HmacStreamR {
        output: Arc::new(RwLock::new(data_stream)),
        tag,
        w_cnt: Arc::clone(&w_cnt),
        len: Arc::clone(&len),
        pending: Arc::clone(&pending),
        buffer,
    };

    let h: H = unsafe { std::mem::uninitialized() };
    let pool = ThreadPoolBuilder::new().num_threads(threads).breadth_first().build().unwrap();

    let writer = HmacStreamW {
        s: Arc::new(ks),
        idx: Arc::new(Mutex::new(0)),
        data_tx,
        tag_tx,
        pool: Arc::new(pool),
        errors: Arc::new(Mutex::new(Vec::new())),
        w_cnt,
        len,
        pending,
        h,
    };

    (writer, reader)
}

pub struct CryptoStreamR {
    output: Arc<RwLock<OrderedStream<u8>>>,
    w_cnt: Arc<AtomicUsize>,
    pending: Arc<AtomicUsize>,
    len: Arc<AtomicUsize>,
    buffer: Arc<AtomicUsize>,
}

pub enum ErrorStreamR {
    IoError(io::Error),
    RecvError(RecvError),
    Other(String),
}

impl From<io::Error> for ErrorStreamR {
    fn from(e: io::Error) -> ErrorStreamR {
        ErrorStreamR::IoError(e)
    }
}

impl From<RecvError> for ErrorStreamR {
    fn from(e: RecvError) -> ErrorStreamR {
        ErrorStreamR::RecvError(e)
    }
}

impl From<&str> for ErrorStreamR {
    fn from(s: &str) -> ErrorStreamR {
        ErrorStreamR::Other(s.into())
    }
}

impl Debug for ErrorStreamR {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ErrorStreamR::IoError(e) => write!(fmt, "{:?}", e),
            ErrorStreamR::RecvError(e) => write!(fmt, "{:?}", e),
            ErrorStreamR::Other(s) => write!(fmt, "{:?}", s),
        }
    }
}

impl CryptoStreamR {
    pub fn squeeze(&self, len: usize) -> Result<Vec<u8>, ErrorStreamR> {
        self.update_size();

        if self.total_len() == 0 {
            if !self.has_writers() {
                Err(io::Error::new(ErrorKind::UnexpectedEof, "no available data").into())
            } else {
                Err(io::Error::new(ErrorKind::Interrupted, "possible unsent data").into())
            }
        } else if self.total_len() < len && self.total_len() > 0 {
            let mut l = self.output.write().expect("error locking output stream");
            match l.squeeze(len) {
                Ok(buf) => {
                    self.len.fetch_sub(buf.len(), Ordering::Relaxed);
                    Ok(buf)
                },
                Err(e) => {
                    match e {
                        Some(err) => Err(err.into()),
                        None => Err(io::Error::new(ErrorKind::UnexpectedEof, "stream empty").into()),
                    }
                }
            }
        } else if self.total_len() >= len {
            if self.len() >= len {
                let mut l = self.output.write().expect("error locking output stream");
                match l.squeeze(len) {
                    Ok(buf) => {
                        self.len.fetch_sub(buf.len(), Ordering::Relaxed);
                        Ok(buf)
                    },
                    Err(e) => {
                        match e {
                            Some(err) => Err(err.into()),
                            None => Err(io::Error::new(ErrorKind::UnexpectedEof, "stream empty").into()),
                        }
                    }
                }
            } else {
                loop {
                    if self.len() >= len {
                        let mut l = self.output.write().expect("error locking output stream");
                        match l.squeeze(len) {
                            Ok(buf) => {
                                self.len.fetch_sub(buf.len(), Ordering::Relaxed);
                                return Ok(buf)
                            },
                            Err(e) => {
                                match e {
                                    Some(err) => return Err(err.into()),
                                    None => return Err(io::Error::new(ErrorKind::UnexpectedEof, "stream empty").into()),
                                }
                            }
                        }
                    } else {
                        // is_empty() will compare against total_len()
                        if self.len() > 0 {
                            let mut l = self.output.write().expect("error locking output stream");
                            l.read_msgs(self.len());
                            drop(l);
                            continue
                        } else {
                            continue
                        }
                    }
                }
            }
        } else {
            Err(io::Error::new(ErrorKind::Other, "unknown error").into())
        }
    }

    pub fn squeeze_timeout(&self, len: usize, d: Duration) -> Result<Vec<u8>, Option<RecvTimeoutError>> {
        let mut l = self.output.write().expect("error locking output stream");
        l.squeeze_timeout(len, d)
    }

    pub fn writer_count(&self) -> usize {
        self.w_cnt.load(Ordering::Relaxed)
    }

    pub fn has_writers(&self) -> bool {
        self.writer_count() != 0
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed) + self.buffered_len()
    }

    pub fn is_empty(&self) -> bool {
        self.update_size();
        self.total_len() == 0
    }

    pub fn pending_len(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    pub fn total_len(&self) -> usize {
        self.pending_len() + self.len()
    }

    pub fn update_size(&self) {
        let l = self.output.read().expect("error locking output stream");
        self.buffer.store(l.size(), Ordering::Relaxed);
    }
}

impl Read for CryptoStreamR {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.update_size();

        if self.total_len() == 0 {
            if !self.has_writers() {
                Err(io::Error::new(ErrorKind::UnexpectedEof, "no available data"))
            } else {
                Err(io::Error::new(ErrorKind::Interrupted, "possible unsent data"))
            }
        } else if self.total_len() < buf.len() && self.total_len() > 0 {
            let mut l = self.output.write().expect("error locking output stream");
            match l.read(buf) {
                Ok(written) => {
                    self.len.fetch_sub(written, Ordering::Relaxed);
                    Ok(written)
                },
                Err(e) => Err(e),
            }
        } else if self.total_len() >= buf.len() {
            if self.len() >= buf.len() {
                let mut l = self.output.write().expect("error locking output stream");
                match l.read(buf) {
                    Ok(written) => {
                        self.len.fetch_sub(written, Ordering::Relaxed);
                        Ok(written)
                    },
                    Err(e) => Err(e),
                }
            } else {
                loop {
                    if self.len() >= buf.len() {
                        let mut l = self.output.write().expect("error locking output stream");
                        match l.read(buf) {
                            Ok(written) => {
                                self.len.fetch_sub(written, Ordering::Relaxed);
                                return Ok(written)
                            },
                            Err(e) => {
                                return Err(e)
                            },
                        }
                    } else {
                        // is_empty() will compare against total_len()
                        if self.len() > 0 {
                            let mut l = self.output.write().expect("error locking output stream");
                            l.read_msgs(self.len());
                            drop(l);
                            continue
                        } else {
                            continue
                        }
                    }
                }
            }
        } else {
            Err(io::Error::new(ErrorKind::Other, "unknown error"))
        }
    }
}

pub struct CryptoStreamW<C: Cipher> {
    k: Arc<MultiKey>,
    n: Arc<MultiNonce>,
    idx: u64,
    ic: u64,
    c: C,
    crypt_tx: Sender<(u64, Vec<u8>)>,
    pool: Arc<ThreadPool>,
    errors: Arc<Mutex<Vec<String>>>,
    w_cnt: Arc<AtomicUsize>,
    pending: Arc<AtomicUsize>,
    len: Arc<AtomicUsize>,
}

impl<C: Cipher> Drop for CryptoStreamW<C> {
    fn drop(&mut self) {
        self.w_cnt.fetch_sub(1, Ordering::Relaxed);
    }
}

impl<C: Cipher> CryptoStreamW<C> {
    pub fn push(&mut self, mut msg: Vec<u8>) {
        self.pending.fetch_add(msg.len(), Ordering::Relaxed);

        let c_tx = self.crypt_tx.clone();
        let c = self.c.clone();
        let key = Arc::clone(&self.k);
        let non = Arc::clone(&self.n);
        let err = Arc::clone(&self.errors);
        let len = Arc::clone(&self.len);
        let pnd = Arc::clone(&self.pending);
        //let mut icl  = self.ic.lock().unwrap();
        //let mut idxl = self.idx.lock().unwrap();
        //let len = Arc::clone(&self.len);

        let idx = self.idx;
        let ic = self.ic;

        self.ic += msg.len() as u64 / 64;
        self.idx += 1;

        //drop(icl);
        //drop(idxl);

        self.pool.spawn(move || {
            match c.mut_crypt(msg.as_mut_slice(), &key, &non, ic) {
                Ok(_) => (),
                Err(_e) => panic!("crypt error"),
            }

            let l = msg.len();
            match c_tx.send((idx, msg)) {
                Ok(_) => {
                    pnd.fetch_sub(l, Ordering::Relaxed);
                    len.fetch_add(l, Ordering::Relaxed);
                },
                Err(e) => {
                    let mut l = err.lock().unwrap();
                    l.push("crypto tx err: ".to_owned() + &e.to_string());
                },
            }
        });
    }
}

impl<C: Cipher> Write for CryptoStreamW<C> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let msg = buf.to_vec();

        self.push(msg);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct HmacStreamR<H: Hmac> {
    output: Arc<RwLock<OrderedStream<u8>>>,
    pub tag: AsyncTag<H>,
    w_cnt: Arc<AtomicUsize>,
    pending: Arc<AtomicUsize>,
    len: Arc<AtomicUsize>,
    buffer: Arc<AtomicUsize>,
}

impl<H: Hmac> HmacStreamR<H> {
    pub fn squeeze(&self, len: usize) -> Result<Vec<u8>, ErrorStreamR> {
        self.update_size();

        if self.total_len() == 0 {
            if !self.has_writers() {
                Err(io::Error::new(ErrorKind::UnexpectedEof, "no available data").into())
            } else {
                Err(io::Error::new(ErrorKind::Interrupted, "possible unsent data").into())
            }
        } else if self.total_len() < len && self.total_len() > 0 {
            let mut l = self.output.write().expect("error locking output stream");
            match l.squeeze(len) {
                Ok(buf) => {
                    self.len.fetch_sub(buf.len(), Ordering::Relaxed);
                    Ok(buf)
                },
                Err(e) => {
                    match e {
                        Some(err) => Err(err.into()),
                        None => Err(io::Error::new(ErrorKind::UnexpectedEof, "stream empty").into()),
                    }
                }
            }
        } else if self.total_len() >= len {
            if self.len() >= len {
                let mut l = self.output.write().expect("error locking output stream");
                match l.squeeze(len) {
                    Ok(buf) => {
                        self.len.fetch_sub(buf.len(), Ordering::Relaxed);
                        Ok(buf)
                    },
                    Err(e) => {
                        match e {
                            Some(err) => Err(err.into()),
                            None => Err(io::Error::new(ErrorKind::UnexpectedEof, "stream empty").into()),
                        }
                    }
                }
            } else {
                loop {
                    if self.len() >= len {
                        let mut l = self.output.write().expect("error locking output stream");
                        match l.squeeze(len) {
                            Ok(buf) => {
                                self.len.fetch_sub(buf.len(), Ordering::Relaxed);
                                return Ok(buf)
                            },
                            Err(e) => {
                                match e {
                                    Some(err) => return Err(err.into()),
                                    None => return Err(io::Error::new(ErrorKind::UnexpectedEof, "stream empty").into()),
                                }
                            }
                        }
                    } else {
                        // is_empty() will compare against total_len()
                        if self.len() > 0 {
                            let mut l = self.output.write().expect("error locking output stream");
                            l.read_msgs(self.len());
                            drop(l);
                            continue
                        } else {
                            continue
                        }
                    }
                }
            }
        } else {
            Err(io::Error::new(ErrorKind::Other, "unknown error").into())
        }
    }

    /*pub fn squeeze_timeout(&self, len: usize, d: Duration) -> Result<Vec<u8>, Option<RecvTimeoutError>> {
        unimplemented!();
    }*/

    pub fn writer_count(&self) -> usize {
        self.w_cnt.load(Ordering::Relaxed)
    }

    pub fn has_writers(&self) -> bool {
        self.writer_count() != 0
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed) + self.buffered_len()
    }

    pub fn is_empty(&self) -> bool {
        self.update_size();
        self.total_len() == 0
    }

    pub fn pending_len(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    pub fn total_len(&self) -> usize {
        self.pending_len() + self.len()
    }

    pub fn update_size(&self) {
        let l = self.output.read().expect("error locking output stream");
        self.buffer.store(l.size(), Ordering::Relaxed);
    }
}

impl<H: Hmac> Read for HmacStreamR<H> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.update_size();

        if self.total_len() == 0 {
            if !self.has_writers() {
                Err(io::Error::new(ErrorKind::UnexpectedEof, "no available data"))
            } else {
                Err(io::Error::new(ErrorKind::Interrupted, "possible unsent data"))
            }
        } else if self.total_len() < buf.len() && self.total_len() > 0 {
            let mut l = self.output.write().expect("error locking output stream");
            match l.read(buf) {
                Ok(written) => {
                    self.len.fetch_sub(written, Ordering::Relaxed);
                    Ok(written)
                },
                Err(e) => Err(e),
            }
        } else if self.total_len() >= buf.len() {
            if self.len() >= buf.len() {
                let mut l = self.output.write().expect("error locking output stream");
                match l.read(buf) {
                    Ok(written) => {
                        self.len.fetch_sub(written, Ordering::Relaxed);
                        Ok(written)
                    },
                    Err(e) => Err(e),
                }
            } else {
                loop {
                    if self.len() >= buf.len() {
                        let mut l = self.output.write().expect("error locking output stream");
                        match l.read(buf) {
                            Ok(written) => {
                                self.len.fetch_sub(written, Ordering::Relaxed);
                                return Ok(written)
                            },
                            Err(e) => {
                                return Err(e)
                            },
                        }
                    } else {
                        // is_empty() will compare against total_len()
                        if self.len() > 0 {
                            let mut l = self.output.write().expect("error locking output stream");
                            l.read_msgs(self.len());
                            drop(l);
                            continue
                        } else {
                            continue
                        }
                    }
                }
            }
        } else {
            Err(io::Error::new(ErrorKind::Other, "unknown error"))
        }
    }
}

#[derive(Clone)]
pub struct HmacStreamW<H: Hmac> {
    s: Arc<KeySalt>,
    idx: Arc<Mutex<u64>>,
    h: H,
    data_tx: Sender<(u64, Vec<u8>)>,
    tag_tx: Sender<(u64, Vec<u8>)>,
    pool: Arc<ThreadPool>,
    errors: Arc<Mutex<Vec<String>>>,
    w_cnt: Arc<AtomicUsize>,
    len: Arc<AtomicUsize>,
    pending: Arc<AtomicUsize>,
}

impl<H: Hmac> Drop for HmacStreamW<H> {
    fn drop(&mut self) {
        self.w_cnt.fetch_sub(1, Ordering::Relaxed);
    }
}

impl<H: Hmac> HmacStreamW<H> {
    pub fn insert(&self, idx: u64, msg: Vec<u8>) {
        self.pending.fetch_add(msg.len(), Ordering::Relaxed);
        let pnd = Arc::clone(&self.pending);

        let c_tx = self.data_tx.clone();
        let t_tx = self.tag_tx.clone();
        //let c = self.c.clone();
        let salt = Arc::clone(&self.s);
        let err = Arc::clone(&self.errors);
        let len = Arc::clone(&self.len);
        let h = self.h.clone();

        self.pool.spawn(move || {
            /*let mut h = Blake2b::with_key(64, &salt);
            h.update(&msg);

            let mut tag = vec![0u8; 64];
            tag.copy_from_slice(h.finalize().as_bytes());*/

            let tag = h.tag(&msg, &*salt, idx).expect("invalid key or salt for this hmac function");

            let l = msg.len();

            match t_tx.send((idx, tag)) {
                Ok(_) => {
                    //println!("sent tag {}", idx);
                },
                Err(e) => {
                    let mut l = err.lock().unwrap();
                    l.push("tag tx err: ".to_owned() + &e.to_string());
                },
            }

            match c_tx.send((idx, msg)) {
                Ok(_) => {
                    pnd.fetch_sub(l, Ordering::Relaxed);
                    len.fetch_add(l, Ordering::Relaxed);
                },
                Err(e) => {
                    let mut l = err.lock().unwrap();
                    l.push("data tx err: ".to_owned() + &e.to_string());
                },
            }
        });
    }

    pub fn push(&self, msg: Vec<u8>) {
        let mut idxl = self.idx.lock().unwrap();

        let idx = *idxl;
        *idxl += 1;

        self.insert(idx, msg);
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    pub fn pending(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    pub fn total_len(&self) -> usize {
        self.len() + self.pending()
    }

    pub fn is_empty(&self) -> bool {
        self.total_len() == 0
    }
}

impl<H: Hmac> Write for HmacStreamW<H> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let msg = buf.to_vec();

        self.push(msg);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        while self.pending() > 0 {}
        Ok(())
    }
}
