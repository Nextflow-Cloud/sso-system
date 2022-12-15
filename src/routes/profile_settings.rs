use std::{collections::HashMap, env, ffi::OsStr, path::Path};

use bytes::BufMut;
use futures_util::TryStreamExt;
use mongodb::bson::doc;
use reqwest::{header::HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};
use warp::{
    header::headers_cloned,
    multipart::{FormData, Part},
    reply::{Json, WithStatus},
    Error, Filter, Rejection, Reply,
};

use crate::{
    authenticate::{authenticate, Authenticate},
    database::profile::get_collection,
};

#[derive(Deserialize, Serialize)]
pub struct ProfileSettingsError {
    error: String,
}

#[derive(Deserialize, Serialize)]
pub struct ProfileSettingsResponse {
    success: bool,
}

pub fn route() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::patch().and(
        warp::path!("user" / "profile")
            .and(headers_cloned().and_then(authenticate))
            .and(warp::header::value("Content-Type"))
            .and(warp::multipart::form().max_length(8_000_000))
            .and_then(handle),
    )
}

async fn multipart_form(user_id: String, parts: Vec<Part>) -> Option<HashMap<String, String>> {
    let mut vars: HashMap<String, String> = HashMap::new();
    for p in parts {
        let field_name = p.name().to_string();
        let org_filename = p.filename();
        let mut file_extension: Option<String> = None;
        if org_filename.is_some() {
            let content_type = p.content_type().unwrap();
            if content_type.starts_with("image/") {
                file_extension = Some(
                    Path::new(org_filename.unwrap())
                        .extension()
                        .and_then(OsStr::to_str)
                        .unwrap()
                        .to_string(),
                );
            } else {
                println!("invalid file type found: {content_type}");
                return None;
            }
        }
        let value = p
            .stream()
            .try_fold(Vec::new(), |mut vec, data| {
                vec.put(data);
                async move { Ok(vec) }
            })
            .await
            .map_err(|e| {
                println!("reading file error: {e}");
            })
            .unwrap();
        if file_extension.is_some() {
            let mut file_path = env::current_dir().unwrap();
            file_path.push("avatars");
            let new_filename = format!("{}.{}", user_id, file_extension.unwrap().as_str());
            file_path.push(new_filename.clone());
            async_std::fs::write(&file_path, value)
                .await
                .map_err(|e| {
                    println!("error writing file: {e}");
                })
                .unwrap();
            vars.insert(field_name, new_filename);
        } else {
            vars.insert(field_name, String::from_utf8(value).unwrap());
        }
    }
    Some(vars)
}

pub async fn handle(
    jwt: Option<Authenticate>,
    content_type: HeaderValue,
    form_data: FormData,
) -> Result<WithStatus<Json>, warp::Rejection> {
    if let Some(jwt) = jwt {
        // Upload avatar along with other form data
        if !content_type
            .to_str()
            .unwrap()
            .starts_with("multipart/form-data")
        {
            let response = ProfileSettingsError {
                error: "Invalid content type".to_string(),
            };
            return Ok(warp::reply::with_status(
                warp::reply::json(&response),
                StatusCode::BAD_REQUEST,
            ));
        }
        let parts: Result<Vec<Part>, Error> = form_data.try_collect().await;
        if let Ok(parts) = parts {
            let form = multipart_form(jwt.jwt_content.id.clone(), parts)
                .await
                .expect("Unexpected error: unable to read form data");
            let collection = get_collection();
            let existing_profile = collection
                .find_one(doc! {"id": jwt.jwt_content.id.clone()}, None)
                .await;
            if let Ok(profile) = existing_profile {
                if profile.is_none() {
                    let response = ProfileSettingsError {
                        error: "Profile not found".to_string(),
                    };
                    return Ok(warp::reply::with_status(
                        warp::reply::json(&response),
                        StatusCode::NOT_FOUND,
                    ));
                }
                let mut update_query = doc! {};
                let display_name = form.get("display_name");
                if let Some(display_name) = display_name {
                    if display_name.len() > 64 {
                        let response = ProfileSettingsError {
                            error: "Display name too long".to_string(),
                        };
                        return Ok(warp::reply::with_status(
                            warp::reply::json(&response),
                            StatusCode::BAD_REQUEST,
                        ));
                    }
                    update_query.insert("display_name", display_name);
                }
                let description = form.get("description");
                if let Some(description) = description {
                    if description.len() > 2048 {
                        let response = ProfileSettingsError {
                            error: "Description too long".to_string(),
                        };
                        return Ok(warp::reply::with_status(
                            warp::reply::json(&response),
                            StatusCode::BAD_REQUEST,
                        ));
                    }
                    update_query.insert("description", description);
                }
                let website = form.get("website");
                if let Some(website) = website {
                    if website.len() > 256 {
                        let response = ProfileSettingsError {
                            error: "Website too long".to_string(),
                        };
                        return Ok(warp::reply::with_status(
                            warp::reply::json(&response),
                            StatusCode::BAD_REQUEST,
                        ));
                    }
                    update_query.insert("website", website);
                }
                let avatar = form.get("avatar");
                if let Some(avatar) = avatar {
                    update_query.insert("avatar", avatar);
                }
                let result = collection.update_one(
                    doc! {"id": jwt.jwt_content.id},
                    update_query,
                    None
                ).await;
                if result.is_ok() {
                    let response = ProfileSettingsResponse { success: true };
                    Ok(warp::reply::with_status(
                        warp::reply::json(&response),
                        StatusCode::OK,
                    ))
                } else {
                    let response = ProfileSettingsError {
                        error: "Failed to update profile".to_string(),
                    };
                    Ok(warp::reply::with_status(
                        warp::reply::json(&response),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            } else {
                let response = ProfileSettingsError {
                    error: "Profile not found".to_string(),
                };
                Ok(warp::reply::with_status(
                    warp::reply::json(&response),
                    StatusCode::NOT_FOUND,
                ))
            }
        } else {
            let response = ProfileSettingsError {
                error: "Invalid body".to_string(),
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&response),
                StatusCode::BAD_REQUEST,
            ))
        }
    } else {
        let response = ProfileSettingsError {
            error: "Unauthorized".to_string(),
        };
        Ok(warp::reply::with_status(
            warp::reply::json(&response),
            StatusCode::UNAUTHORIZED,
        ))
    }
}
