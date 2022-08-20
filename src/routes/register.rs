use base64::decode;
use bcrypt::{hash, hash_with_salt, DEFAULT_COST};
use jsonwebtoken::{encode, EncodingKey, Header};
use mongodb::bson::doc;
use reqwest;
use serde::{Deserialize, Serialize};
use warp::{
    filters::BoxedFilter,
    hyper::StatusCode,
    reply::{Json, WithStatus},
    Filter, Reply,
};

use crate::{
    database::user::User,
    environment::{HCAPTCHA_SECRET, JWT_SECRET, SALT},
    utilities::{generate_id, vec_to_array},
};

use super::login::UserJwt;

#[derive(Deserialize, Serialize)]
pub struct Register {
    username: String,
    password: String,
    display_name: String,
    email: String,
    captcha_token: String,
}

#[derive(Deserialize, Serialize)]
pub struct RegisterError {
    error: String,
}

#[derive(Deserialize, Serialize)]
pub struct RegisterResponse {
    token: String,
}

#[derive(Deserialize, Serialize)]
pub struct HCaptchaResponse {
    success: bool,
    challenge_ts: Option<String>,
    hostname: Option<String>,
    credit: Option<bool>,
    error_codes: Option<Vec<String>>,
}

pub fn route() -> BoxedFilter<(impl Reply,)> {
    warp::post()
        .and(
            warp::path!("api" / "user")
                .and(warp::body::json())
                .and_then(handle),
        )
        .boxed()
}

pub async fn handle(register: Register) -> Result<WithStatus<Json>, warp::Rejection> {
    let client = reqwest::Client::new();
    let result = client
        .post("https://hcaptcha.com/siteverify")
        .query(&[
            ("response", register.captcha_token),
            ("secret", HCAPTCHA_SECRET.to_string()),
        ])
        .send()
        .await;
    if let Ok(r) = result {
        if r.status() == reqwest::StatusCode::OK {
            let text = r
                .text()
                .await
                .expect("Unexpected error: failed to read response");
            let response: HCaptchaResponse = serde_json::from_str(&text)
                .expect("Unexpected error: failed to convert response into JSON");
            if response.success {
                let salt_bytes =
                    decode(&*SALT).expect("Unexpected error: failed to convert salt to bytes");
                let hashed = hash_with_salt(
                    register.email.clone(),
                    DEFAULT_COST,
                    vec_to_array::<u8, 16>(salt_bytes),
                )
                .expect("Unexpected error: failed to hash");
                let password_hash = hash(register.password, DEFAULT_COST)
                    .expect("Unexpected error: failed to hash");
                let collection = crate::database::user::get_collection();
                let user = collection
                    .find_one(
                        doc! {
                            "email_hash": hashed.to_string()
                        },
                        None,
                    )
                    .await;
                if let Ok(u) = user {
                    if u.is_none() {
                        let user_id = generate_id();
                        let user_document = User {
                            id: user_id.clone(),
                            mfa_enabled: false,
                            mfa_secret: None,
                            display_name: register.display_name,
                            username: register.username,
                            email_hash: hashed.to_string(),
                            password_hash: password_hash.to_string(),
                        };
                        let insert_result = collection.insert_one(user_document, None).await;
                        if insert_result.is_err() {
                            let error = RegisterError {
                                error: "Failed to insert into database".to_string(),
                            };
                            Ok(warp::reply::with_status(
                                warp::reply::json(&error),
                                StatusCode::INTERNAL_SERVER_ERROR,
                            ))
                        } else {
                            let jwt_object = UserJwt { id: user_id };
                            let token = encode(
                                &Header::default(),
                                &jwt_object,
                                &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                            )
                            .expect("Unexpected error: failed to encode token");
                            let response = RegisterResponse { token };
                            Ok(warp::reply::with_status(
                                warp::reply::json(&response),
                                StatusCode::OK,
                            ))
                        }
                    } else {
                        let error = RegisterError {
                            error: "User already exists".to_string(),
                        };
                        Ok(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::CONFLICT,
                        ))
                    }
                } else {
                    let error = RegisterError {
                        error: "Failed to query database".to_string(),
                    };
                    Ok(warp::reply::with_status(
                        warp::reply::json(&error),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            } else {
                let error = RegisterError {
                    error: "Invalid hCaptcha token".to_string(),
                };
                Ok(warp::reply::with_status(
                    warp::reply::json(&error),
                    StatusCode::BAD_REQUEST,
                ))
            }
        } else {
            let error = RegisterError {
                error: "Failed to fetch hCaptcha response".to_string(),
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    } else {
        let error = RegisterError {
            error: "Failed to fetch hCaptcha response".to_string(),
        };
        Ok(warp::reply::with_status(
            warp::reply::json(&error),
            StatusCode::INTERNAL_SERVER_ERROR,
        ))
    }
}
