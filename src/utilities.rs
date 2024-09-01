use std::time::Duration;

use actix_extensible_rate_limit::{
    backend::{
        memory::InMemoryBackend, SimpleInputFunctionBuilder, SimpleInputFuture, SimpleOutput,
    },
    HeaderCompatibleOutput, RateLimiter,
};
use actix_web::{dev::ServiceRequest, HttpResponse};
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use lazy_static::lazy_static;
use lettre::{message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncStd1Executor, AsyncTransport, Message};
use rand::{distributions::Alphanumeric, rngs::StdRng, thread_rng, Rng, SeedableRng};
use regex::Regex;

use crate::{environment::{SMTP_FROM, SMTP_PASSWORD, SMTP_SERVER, SMTP_USERNAME}, errors::Error};

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

// generates 10 random 8 digit codes
pub fn generate_codes() -> Vec<String> {
    let mut codes = Vec::new();
    let mut rng = rand::thread_rng();
    for _ in 0..10 {
        let random_number = rng.gen_range(0..100_000_000);
        codes.push(format!("{:08}", random_number));
    }
    codes
}

pub fn create_rate_limiter(
    interval: Duration,
    max_requests: u64,
) -> RateLimiter<
    InMemoryBackend,
    SimpleOutput,
    impl Fn(&ServiceRequest) -> SimpleInputFuture + 'static,
> {
    let backend = InMemoryBackend::builder().build();
    let input = SimpleInputFunctionBuilder::new(interval, max_requests)
        .real_ip_key()
        .build();
    RateLimiter::builder(backend, input)
        .request_denied_response(|o| {
            HttpResponse::from_error(Error::RateLimited {
                remaining: o.remaining,
                reset: o.seconds_until_reset(),
                limit: o.limit,
            })
        })
        .add_headers()
        .build()
}

pub fn create_success_rate_limiter(
    interval: Duration,
    max_requests: u64,
) -> RateLimiter<
    InMemoryBackend,
    SimpleOutput,
    impl Fn(&ServiceRequest) -> SimpleInputFuture + 'static,
> {
    let backend = InMemoryBackend::builder().build();
    let input = SimpleInputFunctionBuilder::new(interval, max_requests)
        .real_ip_key()
        .build();
    RateLimiter::builder(backend, input)
        .fail_open(true)
        .request_denied_response(|o| {
            HttpResponse::from_error(Error::RateLimited {
                remaining: o.remaining,
                reset: o.seconds_until_reset(),
                limit: o.limit,
            })
        })
        .add_headers()
        .build()
}

pub fn generate_continue_token_long() -> String {
    thread_rng().sample_iter(&Alphanumeric).take(128).map(char::from).collect()
}

pub async fn send_reset_email(to: String, token: String) -> crate::errors::Result<()> {
    let Some(from) = &*SMTP_FROM else {
        return Err(Error::EmailMisconfigured);
    };
    let Some(username) = &*SMTP_USERNAME else {
        return Err(Error::EmailMisconfigured);
    };
    let Some(password) = &*SMTP_PASSWORD else {
        return Err(Error::EmailMisconfigured);
    };
    let Some(server) = &*SMTP_SERVER else {
        return Err(Error::EmailMisconfigured);
    };
    let continue_url = format!("https://sso.nextflow.cloud/forgot?token={}", token);
    let email = Message::builder()
        .from(from.parse().map_err(|_| Error::EmailMisconfigured)?)
        .to(to.parse().map_err(|_| Error::InternalEmailError)?)
        .subject("Reset password")
        .header(ContentType::TEXT_PLAIN)
        .body(format!("Hi there! We received a request to reset your password. If this was you, please click the following link to continue.\n\n{}", continue_url))
        .map_err(|_| Error::EmailMisconfigured)?;
    let creds = Credentials::new(username.to_string(), password.to_string());
    let mailer = AsyncSmtpTransport::<AsyncStd1Executor>::relay(server).expect("failed to set server").credentials(creds).build();
    mailer.send(email).await.map_err(|_| Error::InternalEmailError)?;
    Ok(())
}
