#![cfg_attr(feature = "cargo-clippy", allow(clippy::len_zero))]
#![feature(duration_float)]

pub mod async_tag;
pub mod cipher;
pub mod hmac;
pub mod stream;

#[cfg(test)]
mod tests {
    use rust_sodium::{crypto::stream, randombytes::*};
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    use super::{cipher::{self, MultiKey, MultiNonce}, hmac::{self, KeySalt, PolyKey}, stream::*};

    const TEST_MAX_THREADS: usize = 16;
    const TEST_DATA_MB: usize = 16;
    const TEST_DATA_LEN: usize = 1024*1024*TEST_DATA_MB;
    const TEST_CHUNK_LEN: usize = 1024*1024;

    #[test]
    fn consecutive() {
        println!("blake2 {} threaded:", TEST_MAX_THREADS);
        ae_blake2();
        println!("\nblake2 single threaded:");
        ae_blake2_single();

        println!("\npoly1305 {} threaded:", TEST_MAX_THREADS);
        ae_poly1305();
        println!("\npoly1305 single threaded:");
        ae_poly1305_single();

        println!("\nsha3-224 {} threaded:", TEST_MAX_THREADS);
        ae_sha3224();
        println!("\nsha3-224 single threaded:");
        ae_sha3224_single();

        println!("\nsha3-256 {} threaded:", TEST_MAX_THREADS);
        ae_sha3256();
        println!("\nsha3-256 single threaded:");
        ae_sha3256_single();

        println!("\nsha3-384 {} threaded:", TEST_MAX_THREADS);
        ae_sha3384();
        println!("\nsha3-384 single threaded:");
        ae_sha3384_single();

        println!("\nsha3-512 {} threaded:", TEST_MAX_THREADS);
        ae_sha3512();
        println!("\nsha3-512 single threaded:");
        ae_sha3512_single();
    }

    #[test]
    fn ae_blake2() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let s = randombytes(16);
        let sal = KeySalt::Salt(s);

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Blake2b>(sal.clone(), TEST_MAX_THREADS);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        hreader.tag.calculate_async(Duration::from_millis(100));
        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.wait();
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1);

        drop(reader);
        drop(hreader);

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Blake2b>(sal.clone(), TEST_MAX_THREADS);

        timer = Instant::now();

        hreader.tag.calculate_async(Duration::from_millis(100));
        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.wait();

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn ae_poly1305() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);
        let pk = KeySalt::Poly1305(PolyKey::new(k.clone(), n, None));

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Poly1305>(pk, TEST_MAX_THREADS);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.collect_tags(Duration::from_millis(100));
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag[0]:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1[0]);

        drop(reader);
        drop(hreader);

        let pk = KeySalt::Poly1305(PolyKey::new(k.clone(), n, Some(tag1)));

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Poly1305>(pk, TEST_MAX_THREADS);

        timer = Instant::now();

        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.collect_tags(Duration::from_millis(100));

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag[0]:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2[0]);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        assert_eq!(true, PolyKey::verify(tag2));
    }

    #[test]
    fn ae_sha3224() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let s = randombytes(16);
        let sal = KeySalt::Salt(s);

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Sha3224>(sal.clone(), TEST_MAX_THREADS);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        hreader.tag.calculate_async(Duration::from_millis(500));
        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.wait();
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1);

        drop(reader);
        drop(hreader);

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Sha3224>(sal.clone(), TEST_MAX_THREADS);

        timer = Instant::now();

        hreader.tag.calculate_async(Duration::from_millis(500));
        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.wait();

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn ae_sha3256() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let s = randombytes(16);
        let sal = KeySalt::Salt(s);

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Sha3256>(sal.clone(), TEST_MAX_THREADS);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        hreader.tag.calculate_async(Duration::from_millis(500));
        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.wait();
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1);

        drop(reader);
        drop(hreader);

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Sha3256>(sal.clone(), TEST_MAX_THREADS);

        timer = Instant::now();

        hreader.tag.calculate_async(Duration::from_millis(500));
        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.wait();

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn ae_sha3384() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let s = randombytes(16);
        let sal = KeySalt::Salt(s);

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Sha3384>(sal.clone(), TEST_MAX_THREADS);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        hreader.tag.calculate_async(Duration::from_millis(500));
        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.wait();
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1);

        drop(reader);
        drop(hreader);

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Sha3384>(sal.clone(), TEST_MAX_THREADS);

        timer = Instant::now();

        hreader.tag.calculate_async(Duration::from_millis(500));
        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.wait();

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn ae_sha3512() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let s = randombytes(16);
        let sal = KeySalt::Salt(s);

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Sha3512>(sal.clone(), TEST_MAX_THREADS);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        hreader.tag.calculate_async(Duration::from_millis(500));
        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.wait();
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1);

        drop(reader);
        drop(hreader);

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, TEST_MAX_THREADS);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Sha3512>(sal.clone(), TEST_MAX_THREADS);

        timer = Instant::now();

        hreader.tag.calculate_async(Duration::from_millis(500));
        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.wait();

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn ae_blake2_single() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let s = randombytes(16);
        let sal = KeySalt::Salt(s);

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Blake2b>(sal.clone(), 1);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        hreader.tag.calculate_async(Duration::from_millis(100));
        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.wait();
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1);

        drop(reader);
        drop(hreader);

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Blake2b>(sal.clone(), 1);

        timer = Instant::now();

        hreader.tag.calculate_async(Duration::from_millis(100));
        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.wait();

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        //assert_eq!(tag1, tag2);
    }

    #[test]
    fn ae_poly1305_single() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);
        let pk = KeySalt::Poly1305(PolyKey::new(k.clone(), n, None));

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Poly1305>(pk, 1);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.collect_tags(Duration::from_millis(1100));
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag[0]:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1[0]);

        drop(reader);
        drop(hreader);

        let pk = KeySalt::Poly1305(PolyKey::new(k.clone(), n, Some(tag1)));

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Poly1305>(pk, 1);

        timer = Instant::now();

        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.collect_tags(Duration::from_millis(1100));

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag[0]:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2[0]);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        assert_eq!(true, PolyKey::verify(tag2));
    }

    #[test]
    fn ae_sha3224_single() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let s = randombytes(16);
        let sal = KeySalt::Salt(s);

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Sha3224>(sal.clone(), 1);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        hreader.tag.calculate_async(Duration::from_millis(500));
        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.wait();
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1);

        drop(reader);
        drop(hreader);

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Sha3224>(sal.clone(), 1);

        timer = Instant::now();

        hreader.tag.calculate_async(Duration::from_millis(500));
        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.wait();

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn ae_sha3256_single() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let s = randombytes(16);
        let sal = KeySalt::Salt(s);

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Sha3256>(sal.clone(), 1);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        hreader.tag.calculate_async(Duration::from_millis(500));
        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.wait();
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1);

        drop(reader);
        drop(hreader);

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Sha3256>(sal.clone(), 1);

        timer = Instant::now();

        hreader.tag.calculate_async(Duration::from_millis(500));
        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.wait();

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn ae_sha3384_single() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let s = randombytes(16);
        let sal = KeySalt::Salt(s);

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Sha3384>(sal.clone(), 1);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        hreader.tag.calculate_async(Duration::from_millis(500));
        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.wait();
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1);

        drop(reader);
        drop(hreader);

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Sha3384>(sal.clone(), 1);

        timer = Instant::now();

        hreader.tag.calculate_async(Duration::from_millis(500));
        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.wait();

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn ae_sha3512_single() {
        let big_block = vec![0u8; TEST_DATA_LEN];
        let mut sodium_block = vec![0u8; TEST_DATA_LEN];
        let mut stream_block = vec![0u8; TEST_DATA_LEN];
        let mut decrypted_block = vec![0u8; TEST_DATA_LEN];

        let s = randombytes(16);
        let sal = KeySalt::Salt(s);

        let k = stream::chacha20::gen_key();
        let n = stream::chacha20::gen_nonce();

        let key = MultiKey::ChaCha(k.clone());
        let non = MultiNonce::ChaCha(n);

        let (mut writer, reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (hwriter, mut hreader) = hmac_stream::<hmac::Sha3512>(sal.clone(), 1);

        stream::chacha20::stream_xor_inplace(&mut sodium_block, &n, &k);

        let mut timer = Instant::now();

        for chunk in big_block.chunks(TEST_CHUNK_LEN) {
            writer.write_all(&chunk).expect("write error");
        }
        drop(writer);

        hreader.tag.calculate_async(Duration::from_millis(500));
        while let Ok(buf) = reader.squeeze(TEST_CHUNK_LEN) {
            hwriter.push(buf);
        }
        drop(hwriter);

        hreader.read_exact(&mut stream_block).expect("read error");
        //println!("sodium encrypted:\n{:?}\nstream encrypted:\n{:?}\n", &big_block[0..16], &stream_block[0..16]);

        let tag1 = hreader.tag.wait();
        let mut t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag1);

        drop(reader);
        drop(hreader);

        let (mut writer, mut reader) = crypto_stream::<cipher::ChaCha>(key.clone(), non, 1);
        let (mut hwriter, hreader) = hmac_stream::<hmac::Sha3512>(sal.clone(), 1);

        timer = Instant::now();

        hreader.tag.calculate_async(Duration::from_millis(500));
        for chunk in stream_block.chunks(TEST_CHUNK_LEN) {
            hwriter.write_all(&chunk).expect("write error");
        }
        drop(hwriter);

        while let Ok(buf) = hreader.squeeze(TEST_CHUNK_LEN) {
            writer.push(buf);
        }
        drop(writer);

        reader.read_exact(&mut decrypted_block).expect("read error");

        //println!("original:\n{:?}\ndecrypted:\n{:?}\n", &big_block[0..16], &decrypted_block[0..16]);

        let tag2 = hreader.tag.wait();

        t = timer.elapsed();
        println!("time: {:#?} | speed: {:.2} MiB/s\ntag:\n{:?}\n", t, TEST_DATA_MB as f64 / t.as_float_secs(), tag2);

        assert_eq!(sodium_block[..], stream_block[..]);
        assert_eq!(big_block[..], decrypted_block[..]);
        assert_eq!(tag1, tag2);
    }
}
