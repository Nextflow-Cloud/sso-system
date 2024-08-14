use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{web, Responder};
use bcrypt::verify;
use dashmap::DashMap;
use lazy_static::lazy_static;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use totp_rs::{Secret, TOTP};

use crate::{
    authenticate::Authenticate,
    database::{code, user::{self, User}},
    errors::{Error, Result},
    utilities::{generate_codes, random_number},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Mfa {
    password: Option<String>,
    code: Option<String>,
    continue_token: Option<String>,
    stage: i8,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaResponse {
    continue_token: Option<String>,
    success: Option<bool>,
    qr: Option<String>,
    secret: Option<String>,
    codes: Option<Vec<String>>
}

pub struct PendingMfaEnable {
    pub totp: TOTP,
    pub secret: String,
    pub time: u64,
    pub user: User,
}

pub struct PendingMfaDisable {
    pub user: User,
    pub time: u64,
}

lazy_static! {
    pub static ref PENDING_MFA_ENABLES: DashMap<String, PendingMfaEnable> = DashMap::new();
    pub static ref PENDING_MFA_DISABLES: DashMap<String, PendingMfaDisable> = DashMap::new();
}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
    mfa: web::Json<Mfa>,
) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let mfa = mfa.into_inner();
    if mfa.stage == 1 {
        let collection = user::get_collection();
        let user = collection
            .find_one(doc! {"id": jwt.jwt_content.id})
            .await?
            .ok_or(Error::DatabaseError)?;
        if let Some(password) = mfa.password {
            let verified = verify(password, &user.password_hash)
                .expect("Unexpected error: failed to verify password");
            if !verified {
                return Err(Error::IncorrectCredentials);
            }
            if user.mfa_enabled {
                let continue_token = ulid::Ulid::new().to_string();
                let duration = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Unexpected error: time went backwards");
                let login_session = PendingMfaDisable {
                    time: duration.as_secs(),
                    user,
                };
                PENDING_MFA_DISABLES.insert(continue_token.clone(), login_session);
                Ok(web::Json(MfaResponse {
                    continue_token: Some(continue_token),
                    success: None,
                    qr: None,
                    secret: None,
                    codes: None
                }))
            } else {
                let secret = random_number(160);
                let totp = TOTP::new(
                    totp_rs::Algorithm::SHA256,
                    8,
                    1,
                    30,
                    secret.clone(),
                    Some("Nextflow Cloud Technologies".to_string()),
                    user.username.clone(),
                )
                .expect("Unexpected error: failed to initiate TOTP");
                let qr = totp
                    .get_qr_base64()
                    .expect("Unexpected error: failed to generate QR code");
                let continue_token = ulid::Ulid::new().to_string();
                let duration = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Unexpected error: time went backwards");
                let code = Secret::Raw(secret.to_vec()).to_encoded().to_string();
                let session = PendingMfaEnable {
                    time: duration.as_secs(),
                    user,
                    secret: code.clone(),
                    totp,
                };
                PENDING_MFA_ENABLES.insert(continue_token.clone(), session);
                let codes = generate_codes();
                Ok(web::Json(MfaResponse {
                    continue_token: Some(continue_token),
                    qr: Some(qr),
                    secret: Some(code),
                    success: None,
                    codes: Some(codes)
                }))
            }
        } else {
            Err(Error::MissingPassword)
        }
    } else if mfa.stage == 2 {
        let Some(code) = mfa.code else {
            return Err(Error::MissingCode);
        };
        let Some(continue_token) = mfa.continue_token else {
            return Err(Error::MissingContinueToken);
        };
        let enable_session = PENDING_MFA_ENABLES.get(&continue_token);
        if let Some(enable_session) = enable_session {
            let duration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Unexpected error: time went backwards");
            if duration.as_secs() - enable_session.time > 3600 {
                drop(enable_session);
                PENDING_MFA_ENABLES.remove(&continue_token);
                return Err(Error::SessionExpired);
            }
            let current = enable_session
                .totp
                .generate_current()
                .expect("Unexpected error: failed to generate code");
            if current != code {
                return Err(Error::IncorrectCode);
            }
            let collection = user::get_collection();
            collection
                .update_one(
                    doc! {
                        "id": enable_session.user.id.clone(),
                    },
                    doc! {
                        "$set": {
                            "mfa_enabled": true,
                            "mfa_secret": enable_session.secret.clone()
                        }
                    },
                )
                .await?;
            drop(enable_session);
            PENDING_MFA_ENABLES.remove(&continue_token);
            Ok(web::Json(MfaResponse {
                continue_token: None,
                qr: None,
                secret: None,
                success: Some(true),
                codes: None
            }))
        } else {
            let disable_session = PENDING_MFA_DISABLES.get(&continue_token);
            let Some(disable_session) = disable_session else {
                return Err(Error::SessionExpired);
            };
            let duration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Unexpected error: time went backwards");
            if duration.as_secs() - disable_session.time > 3600 {
                drop(disable_session);
                PENDING_MFA_DISABLES.remove(&continue_token);
                return Err(Error::SessionExpired);
            }
            let secret = Secret::Encoded(disable_session.user.mfa_secret.as_ref().unwrap().clone());
            let totp = TOTP::new(
                totp_rs::Algorithm::SHA256,
                8,
                1,
                30,
                secret.to_bytes().unwrap(),
                Some("Nextflow Cloud Technologies".to_string()),
                disable_session.user.id.clone(),
            )
            .expect("Unexpected error: failed to initiate TOTP");
            let current = totp
                .generate_current()
                .expect("Unexpected error: failed to generate code");
            if current != code {
                let codes = code::get_collection();
                let code = codes.find_one(doc!{
                    "code": code,
                    "user_id": &disable_session.user.id
                }).await?;
                let Some(code) = code else {
                    return Err(Error::IncorrectCode);
                };
                codes.delete_one(doc!{
                    "code": code.code
                }).await?;
            }
            let collection = user::get_collection();
            collection
                .update_one(
                    doc! {
                        "id": disable_session.user.id.clone(),
                    },
                    doc! {
                        "$set": {
                            "mfa_enabled": false,
                            "mfa_secret": None::<String>
                        }
                    },
                )
                .await?;
            code::get_collection().delete_many(doc! {
                "user_id": disable_session.user.id.clone()
            }).await?;
            drop(disable_session);
            PENDING_MFA_DISABLES.remove(&continue_token);
            Ok(web::Json(MfaResponse {
                continue_token: None,
                qr: None,
                secret: None,
                success: Some(true),
                codes: None
            }))
        }
    } else {
        Err(Error::InvalidStage)
    }
}
