use actix_web::{Responder, web};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{
    database::profile,
    database::user, authenticate::Authenticate, errors::{Error, Result},
};

#[derive(Deserialize, Serialize)]
pub struct UserResponse {
    id: String,
    username: String,
    mfa_enabled: bool,
    public_email: bool,
    display_name: String,
    description: String,
    website: String,
    avatar: String,
}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let collection = user::get_collection();
    let profile_collection = profile::get_collection();
    let result = collection
        .find_one(
            doc! {
                "id": jwt.jwt_content.id.clone()
            },
            None,
        )
        .await;
    let profile_result = profile_collection
        .find_one(
            doc! {
                "id": jwt.jwt_content.id.clone()
            },
            None,
        )
        .await;
    if let Ok(result) = result {
        if let Some(result) = result {
            if let Ok(profile_result) = profile_result {
                if let Some(profile_result) = profile_result {
                    Ok(web::Json(UserResponse {
                        avatar: profile_result.avatar,
                        description: profile_result.description,
                        display_name: profile_result.display_name,
                        id: jwt.jwt_content.id,
                        mfa_enabled: result.mfa_enabled,
                        public_email: result.public_email,
                        username: result.username,
                        website: profile_result.website,
                    }))
                } else {
                    Err(Error::UserNotFound)
                }
            } else {
                Err(Error::DatabaseError)
            }
        } else {
            Err(Error::UserNotFound)
        }
    } else {
        Err(Error::DatabaseError)
    }
}


