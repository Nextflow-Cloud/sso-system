use std::time::{SystemTime, UNIX_EPOCH};

use bcrypt::verify;
use dashmap::DashMap;
use lazy_static::lazy_static;
use mongodb::bson::doc;
use regex::Regex;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use warp::{
    header::headers_cloned,
    reply::{Json, WithStatus},
    Filter, Rejection,
};

use crate::{
    authenticate::{authenticate, Authenticate},
    database::user::{get_collection, User},
    utilities::generate_id,
};

#[derive(Deserialize, Serialize)]
pub struct AccountSettings {
    username: Option<String>,
    current_password: Option<String>,
    new_password: Option<String>,
    public_email: Option<bool>,

    code: Option<String>,
    continue_token: Option<String>,

    stage: i8,
}

#[derive(Deserialize, Serialize)]
pub struct AccountSettingsResponse {
    success: Option<bool>,
    continue_token: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct AccountSettingsError {
    error: String,
}

pub struct PendingMfa {
    time: u64,
    previous_request: AccountSettings,
    user: User,
}

lazy_static! {
    pub static ref PENDING_MFAS: DashMap<String, PendingMfa> = DashMap::new();
    pub static ref RE: Regex = Regex::new(r"^[0-9A-Za-z_.-]{3,32}$").expect("Unexpected error: failed to process regex");
}

pub fn route() -> impl Filter<Extract = (WithStatus<warp::reply::Json>,), Error = Rejection> + Clone
{
    warp::patch()
        .and(
            warp::path("user")
                .and(warp::path::end())
                .and(headers_cloned().and_then(authenticate))
                .and(warp::body::json())
                .and_then(handle),
        )
        .boxed()
}

pub async fn handle(
    jwt: Option<Authenticate>,
    account_settings: AccountSettings,
) -> Result<WithStatus<Json>, warp::Rejection> {
    if let Some(jwt) = jwt {
        if account_settings.stage == 1 {
            let user_collection = get_collection();
            let user = user_collection
                .find_one(
                    doc! {
                        "id": jwt.jwt_content.id.clone()
                    },
                    None,
                )
                .await;
            if let Ok(user) = user {
                if let Some(user) = user {
                    if let Some(current_password) = account_settings.current_password.clone() {
                        let verified = verify(current_password, &user.password_hash)
                            .expect("Unexpected error: failed to verify password");
                        if verified {
                            if user.mfa_enabled {
                                let continue_token = generate_id();
                                PENDING_MFAS.insert(
                                    continue_token.clone(),
                                    PendingMfa {
                                        time: std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs(),
                                        previous_request: account_settings,
                                        user,
                                    },
                                );
                                return Ok(warp::reply::with_status(
                                    warp::reply::json(&AccountSettingsResponse {
                                        success: None,
                                        continue_token: Some(continue_token),
                                    }),
                                    StatusCode::OK,
                                ));
                            }
                            let mut update_query = doc! {};
                            if let Some(username) = account_settings.username {
                                if !RE.is_match(&username) {
                                    return Ok(warp::reply::with_status(
                                        warp::reply::json(&AccountSettingsError {
                                            error: "Username is too long or contains invalid characters".to_string(),
                                        }),
                                        StatusCode::BAD_REQUEST,
                                    ));
                                }
                                let user = user_collection
                                    .find_one(
                                        doc! {
                                            "username": username.clone()
                                        },
                                        None,
                                    )
                                    .await;
                                if let Ok(user) = user {
                                    if user.is_some() {
                                        return Ok(warp::reply::with_status(
                                            warp::reply::json(&AccountSettingsError {
                                                error: "Username already taken".to_string(),
                                            }),
                                            StatusCode::CONFLICT,
                                        ));
                                    }
                                    update_query.insert("username", username);
                                } else {
                                    return Ok(warp::reply::with_status(
                                        warp::reply::json(&AccountSettingsError {
                                            error: "Failed to query database".to_string(),
                                        }),
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                    ));
                                }
                            }
                            if let Some(password) = account_settings.new_password {
                                let new_password_hash =
                                    bcrypt::hash(password, bcrypt::DEFAULT_COST)
                                        .expect("Unexpected error: failed to hash password");
                                update_query.insert("password_hash", new_password_hash);
                            }
                            if let Some(public_email) = account_settings.public_email {
                                update_query.insert("public_email", public_email);
                            }
                            let update = user_collection
                                .update_one(
                                    doc! {
                                        "id": jwt.jwt_content.id.clone()
                                    },
                                    update_query,
                                    None,
                                )
                                .await;
                            if update.is_err() {
                                return Ok(warp::reply::with_status(
                                    warp::reply::json(&AccountSettingsError {
                                        error: "Failed to update user".to_string(),
                                    }),
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                ));
                            }
                            Ok(warp::reply::with_status(
                                warp::reply::json(&AccountSettingsResponse {
                                    success: Some(true),
                                    continue_token: None,
                                }),
                                StatusCode::OK,
                            ))
                        } else {
                            Ok(warp::reply::with_status(
                                warp::reply::json(&AccountSettingsError {
                                    error: "Current password incorrect".to_string(),
                                }),
                                StatusCode::UNAUTHORIZED,
                            ))
                        }
                    } else {
                        Ok(warp::reply::with_status(
                            warp::reply::json(&AccountSettingsError {
                                error: "Current password not provided".to_string(),
                            }),
                            StatusCode::BAD_REQUEST,
                        ))
                    }
                } else {
                    Ok(warp::reply::with_status(
                        warp::reply::json(&AccountSettingsError {
                            error: "User not found".to_string(),
                        }),
                        StatusCode::NOT_FOUND,
                    ))
                }
            } else {
                Ok(warp::reply::with_status(
                    warp::reply::json(&AccountSettingsError {
                        error: "Failed to query database".to_string(),
                    }),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            }
        } else if account_settings.stage == 2 {
            if let Some(continue_token) = account_settings.continue_token {
                if let Some(pending_mfa) = PENDING_MFAS.get(&continue_token) {
                    let duration = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Unexpected error: time went backwards");
                    if duration.as_secs() - pending_mfa.time > 3600 {
                        drop(pending_mfa);
                        PENDING_MFAS.remove(&continue_token);
                        let error = AccountSettingsError {
                            error: "Session expired".to_string(),
                        };
                        Ok(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::UNAUTHORIZED,
                        ))
                    } else if let Some(code) = account_settings.code {
                        let secret = Secret::Encoded(pending_mfa.user.mfa_secret.clone().unwrap());
                        let totp = TOTP::new(
                            Algorithm::SHA256,
                            8,
                            1,
                            30,
                            secret.to_bytes().unwrap(),
                            Some("Nextflow Cloud Technologies".to_string()),
                            pending_mfa.user.id.clone(),
                        )
                        .expect("Unexpected error: could not create TOTP instance");
                        let current_code = totp
                            .generate_current()
                            .expect("Unexpected error: failed to generate code");
                        if current_code != code {
                            let error = AccountSettingsError {
                                error: "Invalid code".to_string(),
                            };
                            return Ok(warp::reply::with_status(
                                warp::reply::json(&error),
                                StatusCode::UNAUTHORIZED,
                            ));
                        }
                        let mut update_query = doc! {};
                        if let Some(username) = pending_mfa.previous_request.username.clone() {
                            if !RE.is_match(&username) {
                                return Ok(warp::reply::with_status(
                                    warp::reply::json(&AccountSettingsError {
                                        error: "Username is too long or contains invalid characters".to_string(),
                                    }),
                                    StatusCode::BAD_REQUEST,
                                ));
                            }
                            let user = get_collection()
                                .find_one(
                                    doc! {
                                        "username": username.clone()
                                    },
                                    None,
                                )
                                .await;
                            if let Ok(user) = user {
                                if user.is_some() {
                                    return Ok(warp::reply::with_status(
                                        warp::reply::json(&AccountSettingsError {
                                            error: "Username already taken".to_string(),
                                        }),
                                        StatusCode::CONFLICT,
                                    ));
                                }
                                update_query.insert("username", username);
                            } else {
                                return Ok(warp::reply::with_status(
                                    warp::reply::json(&AccountSettingsError {
                                        error: "Failed to query database".to_string(),
                                    }),
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                ));
                            }
                        }
                        if let Some(password) = pending_mfa.previous_request.new_password.clone() {
                            let new_password_hash =
                                bcrypt::hash(password, bcrypt::DEFAULT_COST)
                                    .expect("Unexpected error: failed to hash password");
                            update_query.insert("password_hash", new_password_hash);
                        }
                        if let Some(public_email) = pending_mfa.previous_request.public_email {
                            update_query.insert("public_email", public_email);
                        }
                        let update = get_collection()
                            .update_one(
                                doc! {
                                    "id": jwt.jwt_content.id.clone()
                                },
                                update_query,
                                None,
                            )
                            .await;
                        if update.is_err() {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(&AccountSettingsError {
                                    error: "Failed to update user".to_string(),
                                }),
                                StatusCode::INTERNAL_SERVER_ERROR,
                            ));
                        }
                        drop(pending_mfa);
                        PENDING_MFAS.remove(&continue_token);
                        Ok(warp::reply::with_status(
                            warp::reply::json(&AccountSettingsResponse {
                                success: Some(true),
                                continue_token: None,
                            }),
                            StatusCode::OK,
                        ))
                    } else {
                        Ok(warp::reply::with_status(
                            warp::reply::json(&AccountSettingsError {
                                error: "Code not provided".to_string(),
                            }),
                            StatusCode::BAD_REQUEST,
                        ))
                    }
                } else {
                    Ok(warp::reply::with_status(
                        warp::reply::json(&AccountSettingsError {
                            error: "Invalid session".to_string(),
                        }),
                        StatusCode::UNAUTHORIZED,
                    ))
                }
            } else {
                Ok(warp::reply::with_status(
                    warp::reply::json(&AccountSettingsError {
                        error: "Continue token not provided".to_string(),
                    }),
                    StatusCode::BAD_REQUEST,
                ))
            }
        } else {
            let error = AccountSettingsError {
                error: "Invalid stage".to_string(),
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error),
                StatusCode::BAD_REQUEST,
            ))
        }
    } else {
        let error = "Invalid authorization".to_string();
        Ok(warp::reply::with_status(
            warp::reply::json(&error),
            StatusCode::BAD_REQUEST,
        ))
    }
}

