use warp::{hyper::StatusCode, Filter, Reply, Rejection};

pub mod account_settings;
pub mod delete;
pub mod ip;
pub mod login;
pub mod logout;
pub mod mfa;
pub mod profile_settings;
pub mod register;
pub mod user;
pub mod validate;

pub fn routes() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::path("api")
        .and(
            ip::route()
                .or(login::route())
                .or(logout::route())
                .or(register::route())
                .or(delete::route())
                .or(validate::route())
                .or(account_settings::route())
                .or(profile_settings::route())
                .or(mfa::route())
                .or(user::route())
                .or(warp::path::end().map(|| {
                    warp::reply::with_status(
                        "I'm a teapot - never gonna give you up",
                        StatusCode::IM_A_TEAPOT,
                    )
                })),
        )
        .or(warp::fs::dir("./bundle"))
        .or(warp::fs::file("./bundle/index.html"))
}
