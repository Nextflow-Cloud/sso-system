use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{web, Responder};
use bcrypt::verify;
use dashmap::DashMap;
use lazy_static::lazy_static;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{
    authenticate::Authenticate,
    database::{self, user::{get_collection, User}},
    errors::{Error, Result},
    utilities::USERNAME_RE,
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct AccountSettingsResponse {
    success: Option<bool>,
    continue_token: Option<String>,
}

pub struct PendingMfa {
    pub time: u64,
    pub previous_request: AccountSettings,
    pub user: User,
}

lazy_static! {
    pub static ref PENDING_MFAS: DashMap<String, PendingMfa> = DashMap::new();
}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
    account_settings: web::Json<AccountSettings>,
) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let account_settings = account_settings.into_inner();
    if account_settings.stage == 1 {
        let user_collection = get_collection();
        let user = user_collection
            .find_one(doc! {
                "id": jwt.jwt_content.id.clone()
            })
            .await?
            .ok_or(Error::DatabaseError)?;
        let Some(current_password) = account_settings.current_password.clone() else {
            return Err(Error::MissingPassword);
        };
        let verified = verify(current_password, &user.password_hash)
            .expect("Unexpected error: failed to verify password");
        if !verified {
            return Err(Error::IncorrectCredentials);
        }
        if user.mfa_enabled {
            let continue_token = ulid::Ulid::new().to_string();
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
            return Ok(web::Json(AccountSettingsResponse {
                success: None,
                continue_token: Some(continue_token),
            }));
        }
        let mut update_query = doc! {};
        if let Some(username) = account_settings.username {
            if !USERNAME_RE.is_match(username.trim()) {
                return Err(Error::InvalidUsername);
            }
            let user = user_collection
                .find_one(doc! {
                    "username": username.trim()
                })
                .await?;
            if user.is_some() {
                return Err(Error::UsernameAlreadyTaken);
            }
            update_query.insert("username", username.trim());
        }
        if let Some(password) = account_settings.new_password {
            let new_password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)
                .expect("Unexpected error: failed to hash password");
            update_query.insert("password_hash", new_password_hash);
        }
        if let Some(public_email) = account_settings.public_email {
            update_query.insert("public_email", public_email);
        }
        user_collection
            .update_one(
                doc! {
                    "id": jwt.jwt_content.id.clone()
                },
                update_query,
            )
            .await?;
        Ok(web::Json(AccountSettingsResponse {
            success: Some(true),
            continue_token: None,
        }))
    } else if account_settings.stage == 2 {
        let Some(continue_token) = account_settings.continue_token else {
            return Err(Error::MissingContinueToken);
        };
        let Some(pending_mfa) = PENDING_MFAS.get(&continue_token) else {
            return Err(Error::SessionExpired);
        };
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Unexpected error: time went backwards");
        if duration.as_secs() - pending_mfa.time > 3600 {
            drop(pending_mfa);
            PENDING_MFAS.remove(&continue_token);
            return Err(Error::SessionExpired);
        }
        let Some(code) = account_settings.code else {
            return Err(Error::MissingCode);
        };
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
            let codes = database::code::get_collection();
            let code = codes.find_one(doc!{
                "code": code,
                "user_id": &pending_mfa.user.id
            }).await?;
            let Some(code) = code else {
                return Err(Error::IncorrectCode);
            };
            codes.delete_one(doc!{
                "code": code.code
            }).await?;
        }
        let mut update_query = doc! {};
        if let Some(username) = pending_mfa.previous_request.username.clone() {
            if !USERNAME_RE.is_match(username.trim()) {
                return Err(Error::InvalidUsername);
            }
            let user = get_collection()
                .find_one(doc! {
                    "username": username.trim()
                })
                .await?;
            if user.is_some() {
                return Err(Error::UsernameAlreadyTaken); // FIXME: ??? what was I thinking here? nvm
            }
            update_query.insert("username", username.trim());
        }
        if let Some(password) = pending_mfa.previous_request.new_password.clone() {
            let new_password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)
                .expect("Unexpected error: failed to hash password");
            update_query.insert("password_hash", new_password_hash);
        }
        if let Some(public_email) = pending_mfa.previous_request.public_email {
            update_query.insert("public_email", public_email);
        }
        get_collection()
            .update_one(
                doc! {
                    "id": jwt.jwt_content.id.clone()
                },
                update_query,
            )
            .await?;
        drop(pending_mfa);
        PENDING_MFAS.remove(&continue_token);
        Ok(web::Json(AccountSettingsResponse {
            success: Some(true),
            continue_token: None,
        }))
    } else {
        Err(Error::InvalidStage)
    }
}
