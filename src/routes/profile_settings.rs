use actix_web::{web, Responder};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{
    authenticate::Authenticate,
    database::profile::get_collection,
    errors::{Error, Result},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSettings {
    display_name: Option<String>,
    description: Option<String>,
    website: Option<String>,
    avatar: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSettingsResponse {
    success: bool,
}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
    profile_settings: web::Json<ProfileSettings>,
) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let profile_settings = profile_settings.into_inner();

    let collection = get_collection();
    let existing_profile = collection
        .find_one(doc! {"id": jwt.jwt_content.id.clone()}, None)
        .await;
    if let Ok(profile) = existing_profile {
        if profile.is_none() {
            return Err(Error::DatabaseError);
        }
        let mut update_query = doc! {};
        if let Some(display_name) = profile_settings.display_name {
            if display_name.trim().len() > 64 {
                return Err(Error::DisplayNameTooLong);
            }
            update_query.insert("display_name", display_name.trim());
        }
        if let Some(description) = profile_settings.description {
            if description.trim().len() > 2048 {
                return Err(Error::DescriptionTooLong);
            }
            update_query.insert("description", description.trim());
        }
        if let Some(website) = profile_settings.website {
            if website.trim().len() > 256 {
                return Err(Error::WebsiteTooLong);
            }
            update_query.insert("website", website.trim());
        }
        if let Some(avatar) = profile_settings.avatar {
            // TODO: check CDN for avatar
            update_query.insert("avatar", avatar);
        }
        let result = collection
            .update_one(doc! {"id": jwt.jwt_content.id}, update_query, None)
            .await;
        if result.is_ok() {
            Ok(web::Json(ProfileSettingsResponse { success: true }))
        } else {
            Err(Error::DatabaseError)
        }
    } else {
        Err(Error::DatabaseError)
    }
}
