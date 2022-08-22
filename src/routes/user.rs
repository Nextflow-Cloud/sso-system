// coming soon™ - @Queryzi 2022

use mongodb::bson::doc;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use warp::{filters::BoxedFilter, Reply, reply::{WithStatus, Json}, header::headers_cloned, Filter};

use crate::{database::profile, database::user, authenticate::{Authenticate, authenticate}};

#[derive(Deserialize, Serialize)]
pub struct UserError {
    error: String,
}

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

pub fn route() -> BoxedFilter<(impl Reply,)> {
    warp::get()
        .and(
            warp::path!("user")
                .and(
                    warp::path::param::<String>()
                        .map(Some)
                        .or_else(|_| async { Ok::<(Option<String>,), std::convert::Infallible>((None,)) })
                )
                .and(headers_cloned().and_then(authenticate))
                .and_then(handle)
            )
        .boxed()
}

pub async fn handle(user_id: Option<String>, jwt: Option<Authenticate>) -> Result<WithStatus<Json>, warp::Rejection> {
    // so dude wanna do this together @Queryzi this won't be too hard
    // @Queryzi

    if let Some(j) = jwt {
        if let Some(u) = user_id {
            let collection = user::get_collection();
            let profile_collection = profile::get_collection();
            let result = collection.find_one(doc! {
                "id": u.clone()
            }, None).await;
            let profile_result = profile_collection.find_one(doc! {
                "id": u.clone()
            }, None).await;
            if let Ok(r) = result {
                if let Some(r) = r {
                    if let Ok(pr) = profile_result {
                        if let Some(pr) = pr {
                            let response = UserResponse {
                                avatar: pr.avatar,
                                description: pr.description,
                                display_name: pr.display_name,
                                id: u,
                                mfa_enabled: r.mfa_enabled,
                                public_email: r.public_email,
                                username: r.username,
                                website: pr.website
                            };
                            Ok(warp::reply::with_status(
                                warp::reply::json(&response),
                                StatusCode::OK,
                            ))
                        } else {
                            let error = UserError {
                                error: "User does not exist".to_string(),
                            };
                            Ok(warp::reply::with_status(
                                warp::reply::json(&error),
                                StatusCode::NOT_FOUND,
                            ))
                        }
                    } else {
                        let error = UserError {
                            error: "Could not query database".to_string(),
                        };
                        Ok(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ))
                    }
                } else {
                    let error = UserError {
                        error: "User does not exist".to_string(),
                    };
                    Ok(warp::reply::with_status(
                        warp::reply::json(&error),
                        StatusCode::NOT_FOUND,
                    ))
                }
            } else {
                let error = UserError {
                    error: "Could not query database".to_string(),
                };
                Ok(warp::reply::with_status(
                    warp::reply::json(&error),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            }
        } else {
            let collection = user::get_collection();
            let profile_collection = profile::get_collection();
            let result = collection.find_one(doc! {
                "id": j.jwt_content.id.clone()
            }, None).await;
            let profile_result = profile_collection.find_one(doc! {
                "id": j.jwt_content.id.clone()
            }, None).await;
            if let Ok(r) = result {
                if let Some(r) = r {
                    if let Ok(pr) = profile_result {
                        if let Some(pr) = pr {
                            let response = UserResponse {
                                avatar: pr.avatar,
                                description: pr.description,
                                display_name: pr.display_name,
                                id: j.jwt_content.id,
                                mfa_enabled: r.mfa_enabled,
                                public_email: r.public_email,
                                username: r.username,
                                website: pr.website
                            };
                            Ok(warp::reply::with_status(
                                warp::reply::json(&response),
                                StatusCode::OK,
                            ))
                        } else {
                            let error = UserError {
                                error: "User does not exist".to_string(),
                            };
                            Ok(warp::reply::with_status(
                                warp::reply::json(&error),
                                StatusCode::NOT_FOUND,
                            ))
                        }
                    } else {
                        let error = UserError {
                            error: "Could not query database".to_string(),
                        };
                        Ok(warp::reply::with_status(
                            warp::reply::json(&error),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ))
                    }
                } else {
                    let error = UserError {
                        error: "User does not exist".to_string(),
                    };
                    Ok(warp::reply::with_status(
                        warp::reply::json(&error),
                        StatusCode::NOT_FOUND,
                    ))
                }
            } else {
                let error = UserError {
                    error: "Could not query database".to_string(),
                };
                Ok(warp::reply::with_status(
                    warp::reply::json(&error),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            }
        }
    } else {
        let error = UserError {
            error: "Not authenticated".to_string(),
        };
        Ok(warp::reply::with_status(
            warp::reply::json(&error),
            StatusCode::UNAUTHORIZED,
        ))
    }
    
    // SO: 
    // OFFICIAL API LIMITS: 
    // USERNAME: 32
    // PASSWORD: 256
}
