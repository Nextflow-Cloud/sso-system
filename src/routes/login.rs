use actix_web::{web, Responder};
use bcrypt::verify;
use dashmap::DashMap;
use jsonwebtoken::{encode, EncodingKey, Header};
use lazy_static::lazy_static;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{
    authenticate::UserJwt,
    database::user::User,
    environment::JWT_SECRET,
    errors::{Error, Result},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    stage: i8,
    email: Option<String>,
    continue_token: Option<String>,
    password: Option<String>,
    persist: Option<bool>,
    code: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    mfa_enabled: Option<bool>,
    token: Option<String>,
    continue_token: Option<String>,
}

pub struct PendingLogin {
    pub email: String,
    pub time: u64,
    pub user: User,
}

pub struct PendingMfa {
    pub time: u64,
    pub user: User,
    pub email: String,
}

lazy_static! {
    pub static ref PENDING_LOGINS: DashMap<String, PendingLogin> = DashMap::new();
    pub static ref PENDING_MFAS: DashMap<String, PendingMfa> = DashMap::new();
}

pub async fn handle(login: web::Json<Login>) -> Result<impl Responder> {
    let login = login.into_inner();
    match login.stage {
        1 => {
            let collection = crate::database::user::get_collection();
            if let Some(email) = login.email {
                let result = collection
                    .find_one(
                        doc! {
                            "email": email.clone()
                        },
                        None,
                    )
                    .await;
                if let Ok(user) = result {
                    if let Some(user_exists) = user {
                        let continue_token = ulid::Ulid::new().to_string();
                        let duration = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Unexpected error: time went backwards");
                        let login_session = PendingLogin {
                            email,
                            time: duration.as_secs(),
                            user: user_exists,
                        };
                        PENDING_LOGINS.insert(continue_token.clone(), login_session);
                        Ok(web::Json(LoginResponse {
                            continue_token: Some(continue_token),
                            mfa_enabled: None,
                            token: None,
                        }))
                    } else {
                        Err(Error::IncorrectEmail)
                    }
                } else {
                    Err(Error::DatabaseError)
                }
            } else {
                Err(Error::MissingEmail)
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
                        Err(Error::SessionExpired)
                    } else if let Some(password) = login.password {
                        let verified = verify(password, &pending_login.user.password_hash)
                            .expect("Unexpected error: failed to verify password");
                        if verified {
                            if pending_login.user.mfa_enabled {
                                let continue_token = ulid::Ulid::new().to_string();
                                let pending_mfa = PendingMfa {
                                    time: duration.as_secs(),
                                    user: pending_login.user.clone(),
                                    email: pending_login.email.clone(),
                                };
                                PENDING_MFAS.insert(continue_token.clone(), pending_mfa);
                                drop(pending_login);
                                PENDING_LOGINS.remove(&continue_token);
                                Ok(web::Json(LoginResponse {
                                    token: None,
                                    continue_token: Some(continue_token),
                                    mfa_enabled: Some(true),
                                }))
                            } else {
                                let persist = login.persist.unwrap_or(false);
                                let millis = duration.as_millis();
                                let expires_at = if persist {
                                    millis + 2592000000
                                } else {
                                    millis + 604800000
                                };
                                let jwt_object = UserJwt {
                                    id: pending_login.user.id.clone(),
                                    issued_at: millis,
                                    expires_at,
                                };
                                let token = encode(
                                    &Header::default(),
                                    &jwt_object,
                                    &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                                )
                                .expect("Unexpected error: failed to encode token");
                                drop(pending_login);
                                PENDING_LOGINS.remove(&continue_token);
                                Ok(web::Json(LoginResponse {
                                    token: Some(token),
                                    continue_token: None,
                                    mfa_enabled: Some(false),
                                }))
                            }
                        } else {
                            Err(Error::IncorrectPassword)
                        }
                    } else {
                        Err(Error::MissingPassword)
                    }
                } else {
                    Err(Error::SessionExpired)
                }
            } else {
                Err(Error::MissingContinueToken)
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
                        Err(Error::SessionExpired)
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
                            Err(Error::IncorrectCode)
                        } else {
                            let persist = login.persist.unwrap_or(false);
                            let millis = duration.as_millis();
                            let expires_at = if persist {
                                millis + 2592000000
                            } else {
                                millis + 604800000
                            };
                            let jwt_object = UserJwt {
                                id: mfa_session.user.id.clone(),
                                issued_at: millis,
                                expires_at,
                            };
                            let token = encode(
                                &Header::default(),
                                &jwt_object,
                                &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                            )
                            .expect("Unexpected error: failed to encode token");
                            drop(mfa_session);
                            PENDING_MFAS.remove(&continue_token);
                            Ok(web::Json(LoginResponse {
                                token: Some(token),
                                continue_token: None,
                                mfa_enabled: None,
                            }))
                        }
                    } else {
                        Err(Error::MissingCode)
                    }
                } else {
                    Err(Error::SessionExpired)
                }
            } else {
                Err(Error::MissingContinueToken)
            }
        }
        _ => Err(Error::InvalidStage),
    }
}
