use std::collections::HashSet;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use warp::{
    reply::{Json, WithStatus},
    Filter, Rejection, Reply,
};

use crate::environment::JWT_SECRET;

use super::login::UserJwt;

#[derive(Deserialize, Serialize)]
pub struct Validate {
    token: String,
}

#[derive(Deserialize, Serialize)]
pub struct ValidateError {
    error: String,
}

#[derive(Deserialize, Serialize)]
pub struct ValidateResponse {
    success: bool,
}

pub fn route() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::post().and(
        warp::path("validate")
            .and(warp::body::json())
            .and_then(handle),
    )
}
pub async fn handle(validate: Validate) -> Result<WithStatus<Json>, warp::Rejection> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = HashSet::new();
    validation.validate_exp = false;
    let result = decode::<UserJwt>(
        &validate.token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &validation,
    );
    if result.is_ok() {
        let response = ValidateResponse { success: true };
        Ok(warp::reply::with_status(
            warp::reply::json(&response),
            StatusCode::OK,
        ))
    } else {
        let error = ValidateError {
            error: "Failed to validate JWT".to_string(),
        };
        Ok(warp::reply::with_status(
            warp::reply::json(&error),
            StatusCode::BAD_REQUEST,
        ))
    }
}
