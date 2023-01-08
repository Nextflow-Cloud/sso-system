use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use lazy_static::lazy_static;
use rand::{rngs::StdRng, Rng, SeedableRng};
use regex::Regex;

lazy_static! {
    pub static ref USERNAME_RE: Regex = Regex::new(r"^[0-9A-Za-z_.-]{3,32}$").expect("Unexpected error: failed to process regex");
    pub static ref EMAIL_RE: Regex = Regex::new(r#"^(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$"#).expect("Unexpected error: failed to process regex");
}

pub fn encrypt(buffer: Vec<u8>, encrypt: Aes256Gcm) -> Vec<u8> {
    let mut rng = StdRng::from_entropy();
    let mut nonce_bytes: Vec<u8> = vec![0; 96];
    rng.fill(&mut nonce_bytes[..]);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut encrypted = encrypt.encrypt(nonce, buffer.as_slice()).unwrap();
    let mut result = Vec::new();
    result.append(&mut nonce_bytes);
    result.append(&mut encrypted);
    result
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

pub fn random_number(size: usize) -> Vec<u8> {
    let mut rng = StdRng::from_entropy();
    let mut result: Vec<u8> = vec![0; size];
    rng.fill(&mut result[..]);
    result
}
