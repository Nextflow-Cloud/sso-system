use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{web, Responder};
use bcrypt::{hash, DEFAULT_COST};
use jsonwebtoken::{encode, EncodingKey, Header};
use mongodb::bson::doc;
use reqwest;
use serde::{Deserialize, Serialize};

use crate::{
    authenticate::UserJwt,
    database::{profile::UserProfile, session::Session, user::User},
    environment::{HCAPTCHA_SECRET, JWT_SECRET},
    errors::{Error, Result},
    utilities::{EMAIL_RE, USERNAME_RE},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Register {
    username: String,
    password: String,
    display_name: String,
    email: String,
    captcha_token: String,
    persist: Option<bool>,
    friendly_name: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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

pub async fn handle(register: web::Json<Register>) -> Result<impl Responder> {
    let register = register.into_inner();
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
                if !EMAIL_RE.is_match(register.email.trim()) {
                    return Err(Error::InvalidEmail);
                }
                let password_hash = hash(register.password, DEFAULT_COST)
                    .expect("Unexpected error: failed to hash");
                let collection = crate::database::user::get_collection();
                let user = collection
                    .find_one(
                        doc! {
                            "email": register.email.clone()
                        },
                        None,
                    )
                    .await?;
                if user.is_none() {
                    if register.display_name.trim().len() > 64 {
                        return Err(Error::DisplayNameTooLong);
                    }
                    if !USERNAME_RE.is_match(register.username.trim()) {
                        return Err(Error::InvalidUsername);
                    }
                    let user_id = ulid::Ulid::new().to_string();
                    let user_document = User {
                        id: user_id.clone(),
                        mfa_enabled: false,
                        mfa_secret: None,
                        username: register.username,
                        email: register.email.trim().to_string(),
                        password_hash: password_hash.to_string(),
                        public_email: false,
                        platform_administrator: false,
                    };
                    let profile_document = UserProfile {
                        id: user_id.clone(),
                        display_name: register.display_name.trim().to_string(),
                        description: String::new(),
                        website: String::new(),
                        avatar: "default".to_string(),
                    };
                    collection.insert_one(user_document, None).await?;
                    let profile_collection = crate::database::profile::get_collection();
                    profile_collection.insert_one(profile_document, None).await?;
                    let duration = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Unexpected error: time went backwards");
                    let persist = register.persist.unwrap_or(false);
                    let millis = duration.as_millis();
                    let expires_at = if persist {
                        millis + 2592000000
                    } else {
                        millis + 604800000
                    };
                    let jwt_object = UserJwt {
                        id: user_id.clone(),
                        issued_at: millis,
                        expires_at,
                    };
                    let token = encode(
                        &Header::default(),
                        &jwt_object,
                        &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                    )
                    .expect("Unexpected error: failed to encode token");
                    let sid = ulid::Ulid::new().to_string();
                    let session = Session { 
                        id: sid, 
                        token: token.clone(), 
                        friendly_name: register.friendly_name.unwrap_or("Unknown".to_owned()),
                        user_id,
                    };
                    let sessions = crate::database::session::get_collection();
                    sessions.insert_one(
                        session,
                        None,
                    ).await?;
                    Ok(web::Json(RegisterResponse { token }))
                } else {
                    Err(Error::UserExists)
                }
            } else {
                Err(Error::InvalidCaptcha)
            }
        } else {
            Err(Error::InternalCaptchaError)
        }
    } else {
        Err(Error::InternalCaptchaError)
    }
}
