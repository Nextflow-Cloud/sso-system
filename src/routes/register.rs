use base64::decode;
use bcrypt::{hash, hash_with_salt, DEFAULT_COST};
use jsonwebtoken::{encode, EncodingKey, Header};
use mongodb::bson::doc;
use reqwest;
use serde::{Deserialize, Serialize};
use warp::{
    hyper::StatusCode,
    reply::{Json, WithStatus, WithHeader},
    Filter, Rejection, Reply,
};

use crate::{
    database::{profile::UserProfile, user::User},
    environment::{HCAPTCHA_SECRET, JWT_SECRET, SALT, ROOT_DOMAIN},
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

pub fn route() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::post().and(warp::path("user").and(warp::body::json()).and_then(handle))
}

pub async fn handle(register: Register) -> Result<WithHeader<WithStatus<Json>>, warp::Rejection> {
    let client = reqwest::Client::new();
    let result = client
        .post("https://hcaptcha.com/siteverify")
        .query(&[
            ("response", register.captcha_token),
            ("secret", HCAPTCHA_SECRET.to_string()),
        ])
        .send()
        .await;
    if let Ok(result) = result {
        if result.status() == reqwest::StatusCode::OK {
            let text = result
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
                if let Ok(user) = user {
                    if user.is_none() {
                        let user_id = generate_id();
                        let user_document = User {
                            id: user_id.clone(),
                            mfa_enabled: false,
                            mfa_secret: None,
                            username: register.username,
                            email_hash: hashed.to_string(),
                            password_hash: password_hash.to_string(),
                            public_email: false,
                        };
                        let profile_document = UserProfile {
                            id: user_id.clone(),
                            display_name: register.display_name,
                            description: String::new(),
                            website: String::new(),
                            // TODO: default avatar
                            avatar: "default.png".to_string(),
                        };
                        let insert_result = collection.insert_one(user_document, None).await;
                        let profile_collection = crate::database::profile::get_collection();
                        let profile_result =
                            profile_collection.insert_one(profile_document, None).await;
                        if insert_result.is_err() || profile_result.is_err() {
                            let error = RegisterError {
                                error: "Failed to insert into database".to_string(),
                            };
                            Ok(warp::reply::with_header(warp::reply::with_status(
                                warp::reply::json(&error),
                                StatusCode::INTERNAL_SERVER_ERROR,
                            ), "", ""))
                        } else {
                            let jwt_object = UserJwt { id: user_id };
                            let token = encode(
                                &Header::default(),
                                &jwt_object,
                                &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                            )
                            .expect("Unexpected error: failed to encode token");
                            let response = RegisterResponse { token: token.clone() };
                            Ok(warp::reply::with_header(warp::reply::with_status(
                                warp::reply::json(&response),
                                StatusCode::OK,
                            ), "Set-Cookie", format!("token={}; Max-Age=2147483647; Domain={}; Path=/; Secure", token, ROOT_DOMAIN.as_str())))
                        }
                    } else {
                        let error = RegisterError {
                            error: "User already exists".to_string(),
                        };
                        Ok(warp::reply::with_header(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::CONFLICT,
                        ), "", ""))
                    }
                } else {
                    let error = RegisterError {
                        error: "Failed to query database".to_string(),
                    };
                    Ok(warp::reply::with_header(warp::reply::with_status(
                        warp::reply::json(&error),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ), "", ""))
                }
            } else {
                let error = RegisterError {
                    error: "Invalid hCaptcha token".to_string(),
                };
                Ok(warp::reply::with_header(warp::reply::with_status(
                    warp::reply::json(&error),
                    StatusCode::BAD_REQUEST,
                ), "", ""))
            }
        } else {
            let error = RegisterError {
                error: "Failed to fetch hCaptcha response".to_string(),
            };
            Ok(warp::reply::with_header(warp::reply::with_status(
                warp::reply::json(&error),
                StatusCode::INTERNAL_SERVER_ERROR,
            ), "", ""))
        }
    } else {
        let error = RegisterError {
            error: "Failed to fetch hCaptcha response".to_string(),
        };
        Ok(warp::reply::with_header(warp::reply::with_status(
            warp::reply::json(&error),
            StatusCode::INTERNAL_SERVER_ERROR,
        ), "", ""))
    }
}
