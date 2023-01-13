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
    database::{
        blacklist::{self, Blacklist},
        files::File,
        profile, user,
    },
    errors::{Error, Result},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Delete {
    stage: i8,
    continue_token: Option<String>,
    password: Option<String>,
    code: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResponse {
    success: Option<bool>,
    continue_token: Option<String>,
}

pub struct PendingDelete {
    pub id: String,
    pub mfa_secret: String,
    pub time: u64,
}

lazy_static! {
    pub static ref PENDING_DELETES: DashMap<String, PendingDelete> = DashMap::new();
}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
    delete_user: web::Json<Delete>,
) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let delete_user = delete_user.into_inner();
    if delete_user.stage == 1 {
        if let Some(password) = delete_user.password {
            let collection = user::get_collection();
            let user = collection
                .find_one(
                    doc! {
                        "id": jwt.jwt_content.id.clone()
                    },
                    None,
                )
                .await;
            if let Ok(Some(user)) = user {
                let verified = verify(password, &user.password_hash)
                    .expect("Unexpected error: failed to verify password");
                if verified {
                    if user.mfa_enabled {
                        let continue_token = ulid::Ulid::new().to_string();
                        let duration = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Unexpected error: time went backwards");
                        let delete_session = PendingDelete {
                            id: jwt.jwt_content.id,
                            mfa_secret: user.mfa_secret.unwrap(),
                            time: duration.as_secs(),
                        };
                        PENDING_DELETES.insert(continue_token.clone(), delete_session);
                        Ok(web::Json(DeleteResponse {
                            continue_token: Some(continue_token),
                            success: None,
                        }))
                    } else {
                        let blacklist = blacklist::get_collection();
                        let blacklist_result = blacklist
                            .insert_one(Blacklist { token: jwt.jwt }, None)
                            .await;
                        if blacklist_result.is_ok() {
                            let result = collection
                                .delete_one(
                                    doc! {
                                        "id": &jwt.jwt_content.id
                                    },
                                    None,
                                )
                                .await;
                            let profile = profile::get_collection()
                                .find_one(
                                    doc! {
                                        "id": jwt.jwt_content.id,
                                    },
                                    None,
                                )
                                .await
                                .map_err(|_| Error::DatabaseError)?
                                .ok_or(Error::DatabaseError)?;
                            if let Ok(avatar) = File::get(&profile.avatar).await {
                                avatar.detach().await?;
                            }
                            if result.is_ok() {
                                Ok(web::Json(DeleteResponse {
                                    success: Some(true),
                                    continue_token: None,
                                }))
                            } else {
                                Err(Error::DatabaseError)
                            }
                        } else {
                            Err(Error::DatabaseError)
                        }
                    }
                } else {
                    Err(Error::IncorrectPassword)
                }
            } else {
                Err(Error::DatabaseError)
            }
        } else {
            Err(Error::MissingPassword)
        }
    } else if delete_user.stage == 2 {
        if let Some(ct) = delete_user.continue_token {
            if let Some(c) = delete_user.code {
                let pending_delete = PENDING_DELETES.get(&ct);
                if let Some(pending_delete) = pending_delete {
                    let duration = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Unexpected error: time went backwards");
                    if duration.as_secs() - pending_delete.time > 3600 {
                        drop(pending_delete);
                        PENDING_DELETES.remove(&ct);
                        Err(Error::SessionExpired)
                    } else {
                        let secret = Secret::Encoded(pending_delete.mfa_secret.clone());
                        let totp = TOTP::new(
                            totp_rs::Algorithm::SHA256,
                            8,
                            1,
                            30,
                            secret.to_bytes().unwrap(),
                            Some("Nextflow Cloud Technologies".to_string()),
                            pending_delete.id.clone(),
                        )
                        .expect("Unexpected error: could not create TOTP instance");
                        let current_code = totp
                            .generate_current()
                            .expect("Unexpected error: failed to generate code");
                        if current_code != c {
                            Err(Error::IncorrectCode)
                        } else {
                            let blacklist = blacklist::get_collection();
                            let blacklist_result = blacklist
                                .insert_one(Blacklist { token: jwt.jwt }, None)
                                .await;
                            if blacklist_result.is_ok() {
                                let collection = user::get_collection();
                                let result = collection
                                    .delete_one(
                                        doc! {
                                            "id": jwt.jwt_content.id
                                        },
                                        None,
                                    )
                                    .await;
                                if result.is_ok() {
                                    drop(pending_delete);
                                    PENDING_DELETES.remove(&ct);
                                    Ok(web::Json(DeleteResponse {
                                        success: Some(true),
                                        continue_token: None,
                                    }))
                                } else {
                                    Err(Error::DatabaseError)
                                }
                            } else {
                                Err(Error::DatabaseError)
                            }
                        }
                    }
                } else {
                    Err(Error::SessionExpired)
                }
            } else {
                Err(Error::MissingCode)
            }
        } else {
            Err(Error::MissingContinueToken)
        }
    } else {
        Err(Error::InvalidStage)
    }
}
