use std::net::SocketAddr;

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use warp::{
    filters::BoxedFilter,
    reply::{Json, WithStatus},
    Filter, Reply,
};

#[derive(Deserialize, Serialize)]
pub struct IpResponse {
    ip: String,
}

pub fn route() -> BoxedFilter<(impl Reply,)> {
    warp::get()
        .and(warp::path("ip").and(warp::addr::remote()).and_then(handle))
        .boxed()
}

pub async fn handle(ip: Option<SocketAddr>) -> Result<WithStatus<Json>, warp::Rejection> {
    let error = IpResponse {
        ip: ip.unwrap().ip().to_string(),
    };
    Ok(warp::reply::with_status(
        warp::reply::json(&error),
        StatusCode::OK,
    ))
}
