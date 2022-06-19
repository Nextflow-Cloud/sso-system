use base64::decode;
use bcrypt::{hash_with_salt, verify, DEFAULT_COST};
use dashmap::DashMap;
use jsonwebtoken::{encode, EncodingKey, Header};
use lazy_static::lazy_static;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP};
use warp::{
    filters::BoxedFilter,
    hyper::StatusCode,
    reply::{Json, WithStatus},
    Filter, Reply,
};

use crate::{environment::{JWT_SECRET, SALT}, utilities::{generate_id, vec_to_array}};

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
    id: String,
}

// TODO: move to database
#[derive(Clone, Deserialize, Serialize)]
pub struct User {
    id: String,
    email_hash: String,
    password_hash: String,
    mfa_enabled: bool,
    mfa_secret: Option<String>,
}

lazy_static! {
    pub static ref PENDING_LOGINS: DashMap<String, PendingLogin> = DashMap::new();
    pub static ref PENDING_MFAS: DashMap<String, PendingMfa> = DashMap::new();
}

pub fn route() -> BoxedFilter<(impl Reply,)> {
    warp::post()
        .and(
            warp::path!("api" / "login")
                .and(warp::body::json())
                .and_then(handle),
        )
        .boxed()
}

pub async fn handle(login: Login) -> Result<WithStatus<Json>, warp::Rejection> {
    match login.stage {
        1 => {
            let collection = crate::database::get_database().collection::<User>("users");
            let salt_bytes =
                decode(&*SALT).expect("Unexpected error: failed to convert salt to bytes");
            if let Some(e) = login.email {
                let hashed =
                    hash_with_salt(e.clone(), DEFAULT_COST, vec_to_array::<u8, 16>(salt_bytes))
                        .expect("Unexpected error: failed to hash");
                let result = collection
                    .find_one(
                        doc! {
                            "email_hash": hashed.to_string()
                        },
                        None,
                    )
                    .await;
                if let Ok(u) = result {
                    if let Some(user_exists) = u {
                        let continue_token = generate_id();
                        let duration = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Unexpected error: time went backwards");
                        let login_session = PendingLogin {
                            email: e,
                            time: duration.as_secs(),
                            user: user_exists,
                        };
                        PENDING_LOGINS.insert(continue_token.clone(), login_session);
                        let response = LoginResponse {
                            continue_token: Some(continue_token),
                            mfa_enabled: None,
                            token: None,
                        };
                        Ok(warp::reply::with_status(
                            warp::reply::json(&response),
                            StatusCode::OK,
                        ))
                    } else {
                        let error = LoginError {
                            error: "Unknown user".to_string(),
                        };
                        Ok(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::UNAUTHORIZED,
                        ))
                    }
                } else {
                    let error = LoginError {
                        error: "Database error".to_string(),
                    };
                    Ok(warp::reply::with_status(
                        warp::reply::json(&error),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            } else {
                let error = LoginError {
                    error: "No email provided".to_string(),
                };
                Ok(warp::reply::with_status(
                    warp::reply::json(&error),
                    StatusCode::BAD_REQUEST,
                ))
            }
        }
        2 => {
            if let Some(ct) = login.continue_token {
                let pending_login = PENDING_LOGINS.get(&ct);
                if let Some(l) = pending_login {
                    let duration = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Unexpected error: time went backwards");
                    if duration.as_secs() - l.time > 3600 {
                        let error = LoginError {
                            error: "Session expired".to_string(),
                        };
                        Ok(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::UNAUTHORIZED,
                        ))
                    } else if let Some(p) = login.password {
                        let verified = verify(p, &l.user.password_hash)
                            .expect("Unexpected error: failed to verify password");
                        if verified {
                            if l.user.mfa_enabled {
                                let continue_token = generate_id();
                                let duration = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("Unexpected error: time went backwards");
                                let pending_mfa = PendingMfa {
                                    time: duration.as_secs(),
                                    user: l.user.clone(),
                                    email: l.email.clone(),
                                };
                                PENDING_MFAS.insert(continue_token.clone(), pending_mfa);
                                let response = LoginResponse {
                                    token: None,
                                    continue_token: Some(continue_token),
                                    mfa_enabled: Some(true),
                                };
                                Ok(warp::reply::with_status(
                                    warp::reply::json(&response),
                                    StatusCode::OK,
                                ))
                            } else {
                                let jwt_object = UserJwt {
                                    id: l.user.id.clone(),
                                };
                                let token = encode(
                                    &Header::default(),
                                    &jwt_object,
                                    &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                                )
                                .expect("Unexpected error: failed to encode token");
                                let response = LoginResponse {
                                    token: Some(token),
                                    continue_token: None,
                                    mfa_enabled: Some(false),
                                };
                                Ok(warp::reply::with_status(
                                    warp::reply::json(&response),
                                    StatusCode::OK,
                                ))
                            }
                        } else {
                            let error = LoginError {
                                error: "Invalid password".to_string(),
                            };
                            Ok(warp::reply::with_status(
                                warp::reply::json(&error),
                                StatusCode::UNAUTHORIZED,
                            ))
                        }
                    } else {
                        let error = LoginError {
                            error: "No password provided".to_string(),
                        };
                        Ok(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::BAD_REQUEST,
                        ))
                    }
                } else {
                    let error = LoginError {
                        error: "Session does not exist".to_string(),
                    };
                    Ok(warp::reply::with_status(
                        warp::reply::json(&error),
                        StatusCode::UNAUTHORIZED,
                    ))
                }
            } else {
                let error = LoginError {
                    error: "No continue token provided".to_string(),
                };
                Ok(warp::reply::with_status(
                    warp::reply::json(&error),
                    StatusCode::BAD_REQUEST,
                ))
            }
        }
        3 => {
            if let Some(ct) = login.continue_token {
                let mfa_session = PENDING_MFAS.get(&ct);
                if let Some(m) = mfa_session {
                    let duration = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Unexpected error: time went backwards");
                    if duration.as_secs() - m.time > 3600 {
                        let error = LoginError {
                            error: "Session expired".to_string(),
                        };
                        Ok(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::UNAUTHORIZED,
                        ))
                    } else if let Some(c) = login.code {
                        let totp = TOTP::new(
                            Algorithm::SHA256,
                            8,
                            1,
                            30,
                            m.user.mfa_secret.as_ref().unwrap(),
                            Some("Nextflow Cloud Technologies".to_string()),
                            m.email.clone(),
                        )
                        .expect("Unexpected error: could not create TOTP instance");
                        let current_code = totp
                            .generate_current()
                            .expect("Unexpected error: failed to generate code");
                        if current_code != c {
                            let error = LoginError {
                                error: "Invalid code".to_string(),
                            };
                            Ok(warp::reply::with_status(
                                warp::reply::json(&error),
                                StatusCode::UNAUTHORIZED,
                            ))
                        } else {
                            let jwt_object = UserJwt {
                                id: m.user.id.clone(),
                            };
                            let token = encode(
                                &Header::default(),
                                &jwt_object,
                                &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                            )
                            .expect("Unexpected error: failed to encode token");
                            let response = LoginResponse {
                                token: Some(token),
                                continue_token: None,
                                mfa_enabled: None,
                            };
                            Ok(warp::reply::with_status(
                                warp::reply::json(&response),
                                StatusCode::OK,
                            ))
                        }
                    } else {
                        let error = LoginError {
                            error: "No code provided".to_string(),
                        };
                        Ok(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::BAD_REQUEST,
                        ))
                    }
                } else {
                    let error = LoginError {
                        error: "Session does not exist".to_string(),
                    };
                    Ok(warp::reply::with_status(
                        warp::reply::json(&error),
                        StatusCode::BAD_REQUEST,
                    ))
                }
            } else {
                let error = LoginError {
                    error: "No continue token provided".to_string(),
                };
                Ok(warp::reply::with_status(
                    warp::reply::json(&error),
                    StatusCode::BAD_REQUEST,
                ))
            }
        }
        _ => {
            let error = LoginError {
                error: "Invalid stage".to_string(),
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error),
                StatusCode::BAD_REQUEST,
            ))
        }
    }
}
