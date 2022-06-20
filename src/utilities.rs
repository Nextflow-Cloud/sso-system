use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use rand::{rngs::StdRng, Rng, SeedableRng};

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

pub fn generate(random: fn(usize) -> Vec<u8>, alphabet: &[char], size: usize) -> String {
    assert!(
        alphabet.len() <= u8::max_value() as usize,
        "The alphabet cannot be longer than a `u8` (to comply with the `random` function)"
    );
    let mask = alphabet.len().next_power_of_two() - 1;
    let step: usize = 8 * size / 5;
    let mut id = String::with_capacity(size);
    loop {
        let bytes = random(step);
        for &byte in &bytes {
            let byte = byte as usize & mask;
            if alphabet.len() > byte {
                id.push(alphabet[byte]);
                if id.len() == size {
                    return id;
                }
            }
        }
    }
}

pub fn generate_id() -> String {
    generate(
        random_number,
        &[
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        ],
        32,
    )
}
