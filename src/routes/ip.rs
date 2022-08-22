use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
};

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use warp::{
    addr::remote,
    filters::BoxedFilter,
    reply::{Json, WithStatus},
    Filter, Reply,
};
use warp_real_ip::get_forwarded_for;

#[derive(Deserialize, Serialize)]
pub struct IpResponse {
    ip: String,
}

pub fn real_ip() -> impl Filter<Extract = (Option<IpAddr>,), Error = Infallible> + Clone {
    remote().and(get_forwarded_for()).map(
        move |addr: Option<SocketAddr>, forwarded_for: Vec<IpAddr>| {
            addr.map(|addr| forwarded_for.first().copied().unwrap_or_else(|| addr.ip()))
        },
    )
}

pub fn route() -> BoxedFilter<(impl Reply,)> {
    warp::get()
        .and(warp::path("ip").and(real_ip()).and_then(handle))
        .boxed()
}

pub async fn handle(ip: Option<IpAddr>) -> Result<WithStatus<Json>, warp::Rejection> {
    let error = IpResponse {
        ip: ip.unwrap().to_string(),
    };
    Ok(warp::reply::with_status(
        warp::reply::json(&error),
        StatusCode::OK,
    ))
}
