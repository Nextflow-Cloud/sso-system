use base64::decode;
use bcrypt::{hash_with_salt, verify, DEFAULT_COST};
use dashmap::DashMap;
use jsonwebtoken::{encode, EncodingKey, Header};
use lazy_static::lazy_static;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};
use warp::{
    hyper::StatusCode,
    reply::{Json, WithStatus, WithHeader},
    Filter, Rejection, Reply,
};

use crate::{
    database::user::User,
    environment::{JWT_SECRET, SALT, ROOT_DOMAIN},
    utilities::{generate_id, vec_to_array},
};

#[derive(Deserialize, Serialize)]
pub struct Login {
    stage: i8,
    email: Option<String>,
    continue_token: Option<String>,
    password: Option<String>,
    persist: Option<bool>,
    code: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct LoginError {
    error: String,
}

#[derive(Deserialize, Serialize)]
pub struct LoginResponse {
    mfa_enabled: Option<bool>,
    token: Option<String>,
    continue_token: Option<String>,
}

pub struct PendingLogin {
    email: String,
    time: u64,
    user: User,
}

pub struct PendingMfa {
    time: u64,
    user: User,
    email: String,
}

#[derive(Deserialize, Serialize)]
pub struct UserJwt {
    pub(crate) id: String,
}

lazy_static! {
    pub static ref PENDING_LOGINS: DashMap<String, PendingLogin> = DashMap::new();
    pub static ref PENDING_MFAS: DashMap<String, PendingMfa> = DashMap::new();
}

pub fn route() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::post().and(warp::path("login").and(warp::body::json()).and_then(handle))
}

pub async fn handle(login: Login) -> Result<WithHeader<WithStatus<Json>>, warp::Rejection> {
    match login.stage {
        1 => {
            let collection = crate::database::user::get_collection();
            let salt_bytes =
                decode(&*SALT).expect("Unexpected error: failed to convert salt to bytes");
            if let Some(email) = login.email {
                let hashed = hash_with_salt(
                    email.clone(),
                    DEFAULT_COST,
                    vec_to_array::<u8, 16>(salt_bytes),
                )
                .expect("Unexpected error: failed to hash");
                let result = collection
                    .find_one(
                        doc! {
                            "email_hash": hashed.to_string()
                        },
                        None,
                    )
                    .await;
                if let Ok(user) = result {
                    if let Some(user_exists) = user {
                        let continue_token = generate_id();
                        let duration = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Unexpected error: time went backwards");
                        let login_session = PendingLogin {
                            email,
                            time: duration.as_secs(),
                            user: user_exists,
                        };
                        PENDING_LOGINS.insert(continue_token.clone(), login_session);
                        let response = LoginResponse {
                            continue_token: Some(continue_token),
                            mfa_enabled: None,
                            token: None,
                        };
                        Ok(warp::reply::with_header(warp::reply::with_status(
                            warp::reply::json(&response),
                            StatusCode::OK,
                        ), "", ""))
                    } else {
                        let error = LoginError {
                            error: "Unknown user".to_string(),
                        };
                        Ok(warp::reply::with_header(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::UNAUTHORIZED,
                        ), "", ""))
                    }
                } else {
                    let error = LoginError {
                        error: "Database error".to_string(),
                    };
                    Ok(warp::reply::with_header(warp::reply::with_status(
                        warp::reply::json(&error),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ), "", ""))
                }
            } else {
                let error = LoginError {
                    error: "No email provided".to_string(),
                };
                Ok(warp::reply::with_header(warp::reply::with_status(
                    warp::reply::json(&error),
                    StatusCode::BAD_REQUEST,
                ), "", ""))
            }
        }
        2 => {
            if let Some(continue_token) = login.continue_token {
                let pending_login = PENDING_LOGINS.get(&continue_token);
                if let Some(pending_login) = pending_login {
                    let duration = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Unexpected error: time went backwards");
                    if duration.as_secs() - pending_login.time > 3600 {
                        drop(pending_login);
                        PENDING_LOGINS.remove(&continue_token);
                        let error = LoginError {
                            error: "Session expired".to_string(),
                        };
                        Ok(warp::reply::with_header(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::UNAUTHORIZED,
                        ), "", ""))
                    } else if let Some(password) = login.password {
                        let verified = verify(password, &pending_login.user.password_hash)
                            .expect("Unexpected error: failed to verify password");
                        if verified {
                            if pending_login.user.mfa_enabled {
                                let continue_token = generate_id();
                                let duration = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("Unexpected error: time went backwards");
                                let pending_mfa = PendingMfa {
                                    time: duration.as_secs(),
                                    user: pending_login.user.clone(),
                                    email: pending_login.email.clone(),
                                };
                                PENDING_MFAS.insert(continue_token.clone(), pending_mfa);
                                drop(pending_login);
                                PENDING_LOGINS.remove(&continue_token);
                                let response = LoginResponse {
                                    token: None,
                                    continue_token: Some(continue_token),
                                    mfa_enabled: Some(true),
                                };
                                Ok(warp::reply::with_header(warp::reply::with_status(
                                    warp::reply::json(&response),
                                    StatusCode::OK,
                                ), "", ""))
                            } else {
                                let jwt_object = UserJwt {
                                    id: pending_login.user.id.clone(),
                                };
                                let token = encode(
                                    &Header::default(),
                                    &jwt_object,
                                    &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                                )
                                .expect("Unexpected error: failed to encode token");
                                drop(pending_login);
                                PENDING_LOGINS.remove(&continue_token);
                                let response = LoginResponse {
                                    token: Some(token.clone()),
                                    continue_token: None,
                                    mfa_enabled: Some(false),
                                };
                                Ok(warp::reply::with_header(warp::reply::with_status(
                                    warp::reply::json(&response),
                                    StatusCode::OK,
                                ), "Set-Cookie", format!("token={}; Max-Age=2147483647; Domain={}; Path=/; Secure", token, ROOT_DOMAIN.as_str())))
                            }
                        } else {
                            let error = LoginError {
                                error: "Invalid password".to_string(),
                            };
                            Ok(warp::reply::with_header(warp::reply::with_status(
                                warp::reply::json(&error),
                                StatusCode::UNAUTHORIZED,
                            ), "", ""))
                        }
                    } else {
                        let error = LoginError {
                            error: "No password provided".to_string(),
                        };
                        Ok(warp::reply::with_header(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::BAD_REQUEST,
                        ), "", ""))
                    }
                } else {
                    let error = LoginError {
                        error: "Session does not exist".to_string(),
                    };
                    Ok(warp::reply::with_header(warp::reply::with_status(
                        warp::reply::json(&error),
                        StatusCode::UNAUTHORIZED,
                    ), "", ""))
                }
            } else {
                let error = LoginError {
                    error: "No continue token provided".to_string(),
                };
                Ok(warp::reply::with_header(warp::reply::with_status(
                    warp::reply::json(&error),
                    StatusCode::BAD_REQUEST,
                ), "", ""))
            }
        }
        3 => {
            if let Some(continue_token) = login.continue_token {
                let mfa_session = PENDING_MFAS.get(&continue_token);
                if let Some(mfa_session) = mfa_session {
                    let duration = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Unexpected error: time went backwards");
                    if duration.as_secs() - mfa_session.time > 3600 {
                        drop(mfa_session);
                        PENDING_MFAS.remove(&continue_token);
                        let error = LoginError {
                            error: "Session expired".to_string(),
                        };
                        Ok(warp::reply::with_header(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::UNAUTHORIZED,
                        ), "", ""))
                    } else if let Some(code) = login.code {
                        let secret = Secret::Encoded(mfa_session.user.mfa_secret.clone().unwrap());
                        let totp = TOTP::new(
                            Algorithm::SHA256,
                            8,
                            1,
                            30,
                            secret.to_bytes().unwrap(),
                            Some("Nextflow Cloud Technologies".to_string()),
                            mfa_session.email.clone(),
                        )
                        .expect("Unexpected error: could not create TOTP instance");
                        let current_code = totp
                            .generate_current()
                            .expect("Unexpected error: failed to generate code");
                        if current_code != code {
                            let error = LoginError {
                                error: "Invalid code".to_string(),
                            };
                            Ok(warp::reply::with_header(warp::reply::with_status(
                                warp::reply::json(&error),
                                StatusCode::UNAUTHORIZED,
                            ), "", ""))
                        } else {
                            let jwt_object = UserJwt {
                                id: mfa_session.user.id.clone(),
                            };
                            let token = encode(
                                &Header::default(),
                                &jwt_object,
                                &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                            )
                            .expect("Unexpected error: failed to encode token");
                            drop(mfa_session);
                            PENDING_MFAS.remove(&continue_token);
                            let response = LoginResponse {
                                token: Some(token.clone()),
                                continue_token: None,
                                mfa_enabled: None,
                            };
                            Ok(warp::reply::with_header(warp::reply::with_status(
                                warp::reply::json(&response),
                                StatusCode::OK,
                            ), "Set-Cookie", format!("token={}; Max-Age=2147483647; Domain={}; Path=/; Secure", token, ROOT_DOMAIN.as_str())))
                        }
                    } else {
                        let error = LoginError {
                            error: "No code provided".to_string(),
                        };
                        Ok(warp::reply::with_header(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::BAD_REQUEST,
                        ), "", ""))
                    }
                } else {
                    let error = LoginError {
                        error: "Session does not exist".to_string(),
                    };
                    Ok(warp::reply::with_header(warp::reply::with_status(
                        warp::reply::json(&error),
                        StatusCode::BAD_REQUEST,
                    ), "", ""))
                }
            } else {
                let error = LoginError {
                    error: "No continue token provided".to_string(),
                };
                Ok(warp::reply::with_header(warp::reply::with_status(
                    warp::reply::json(&error),
                    StatusCode::BAD_REQUEST,
                ), "", ""))
            }
        }
        _ => {
            let error = LoginError {
                error: "Invalid stage".to_string(),
            };
            Ok(warp::reply::with_header(warp::reply::with_status(
                warp::reply::json(&error),
                StatusCode::BAD_REQUEST,
            ), "", ""))
        }
    }
}
