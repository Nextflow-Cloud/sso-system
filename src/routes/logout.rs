use reqwest::{
    header::{HeaderMap, HeaderValue},
    StatusCode,
};
use serde::{Deserialize, Serialize};
use warp::{
    filters::BoxedFilter,
    header::headers_cloned,
    reply::{Json, WithStatus},
    Filter,
};

use crate::{
    authenticate::{authenticate, Authenticate},
    database::blacklist::{get_collection, Blacklist},
};

#[derive(Deserialize, Serialize)]
pub struct LogoutResponse {
    success: bool,
}

#[derive(Deserialize, Serialize)]
pub struct LogoutError {
    error: String,
}

pub fn route() -> BoxedFilter<(WithStatus<warp::reply::Json>,)> {
    warp::delete()
        .and(
            warp::path("login")
                .and(
                    headers_cloned()
                        .map(move |headers: HeaderMap<HeaderValue>| headers)
                        .and_then(authenticate),
                )
                .and_then(handle),
        )
        .boxed()
}

pub async fn handle(jwt: Option<Authenticate>) -> Result<WithStatus<Json>, warp::Rejection> {
    if let Some(j) = jwt {
        let blacklist = get_collection();
        let document = Blacklist { token: j.jwt };
        let result = blacklist.insert_one(document, None).await;
        if result.is_ok() {
            let error = LogoutResponse { success: true };
            Ok(warp::reply::with_status(
                warp::reply::json(&error),
                StatusCode::OK,
            ))
        } else {
            let error = LogoutError {
                error: "Failed to write to database".to_string(),
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    } else {
        let error = LogoutError {
            error: "Invalid authorization".to_string(),
        };
        Ok(warp::reply::with_status(
            warp::reply::json(&error),
            StatusCode::UNAUTHORIZED,
        ))
    }
}
