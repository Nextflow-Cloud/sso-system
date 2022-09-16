use mongodb::bson::doc;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use warp::{
    header::headers_cloned,
    reply::{Json, WithStatus},
    Filter, Rejection, Reply,
};

use crate::{
    authenticate::{authenticate, Authenticate},
    database::profile,
    database::user,
};

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

pub fn route() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::get().and(
        warp::path!("user")
            .and(
                warp::path::param::<String>().map(Some).or_else(|_| async {
                    Ok::<(Option<String>,), std::convert::Infallible>((None,))
                }),
            )
            .and(headers_cloned().and_then(authenticate))
            .and_then(handle),
    )
}

pub async fn handle(
    user_id: Option<String>,
    jwt: Option<Authenticate>,
) -> Result<WithStatus<Json>, warp::Rejection> {
    if let Some(jwt) = jwt {
        if let Some(user_id) = user_id {
            let collection = user::get_collection();
            let profile_collection = profile::get_collection();
            let result = collection
                .find_one(
                    doc! {
                        "id": user_id.clone()
                    },
                    None,
                )
                .await;
            let profile_result = profile_collection
                .find_one(
                    doc! {
                        "id": user_id.clone()
                    },
                    None,
                )
                .await;
            if let Ok(result) = result {
                if let Some(result) = result {
                    if let Ok(profile_result) = profile_result {
                        if let Some(profile_result) = profile_result {
                            let response = UserResponse {
                                avatar: profile_result.avatar,
                                description: profile_result.description,
                                display_name: profile_result.display_name,
                                id: user_id,
                                mfa_enabled: result.mfa_enabled,
                                public_email: result.public_email,
                                username: result.username,
                                website: profile_result.website,
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
                            let response = UserResponse {
                                avatar: profile_result.avatar,
                                description: profile_result.description,
                                display_name: profile_result.display_name,
                                id: jwt.jwt_content.id,
                                mfa_enabled: result.mfa_enabled,
                                public_email: result.public_email,
                                username: result.username,
                                website: profile_result.website,
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

    // OFFICIAL API LIMITS:
    // USERNAME: 32
    // PASSWORD: 256
}
