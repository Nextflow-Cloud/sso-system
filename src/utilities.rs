use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::fmt::Write;

pub fn encrypt(buffer: Vec<u8>, encrypt: Option<Aes256Gcm>) -> Vec<u8> {
    if let Some(e) = encrypt {
        let mut nonce_bytes = random_number(96);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut encrypted = e.encrypt(nonce, buffer.as_slice()).unwrap();
        let mut result = Vec::new();
        result.append(&mut nonce_bytes);
        result.append(&mut encrypted);
        result
    } else {
        buffer
    }
}

pub fn decrypt(mut buffer: Vec<u8>, encrypt: Option<Aes256Gcm>) -> Vec<u8> {
    if let Some(e) = encrypt {
        let data = buffer.split_off(96);
        let nonce = Nonce::from_slice(&buffer);
        let decrypted = e.decrypt(nonce, data.as_slice()).unwrap();
        decrypted
    } else {
        buffer
    }
}

pub fn vec_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

pub fn random_number(size: usize) -> Vec<u8> {
    let mut rng = StdRng::from_entropy();
    let mut result: Vec<u8> = vec![0; size];
    rng.fill(&mut result[..]);
    result
}

pub fn generate_id() -> String {
    let length = 32;
    let mut s = String::with_capacity(2 * length);
    for byte in random_number(length) {
        write!(s, "{byte:02X}").expect("Unable to write to string");
    }
    s
}
