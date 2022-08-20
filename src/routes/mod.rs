use warp::{filters::BoxedFilter, hyper::StatusCode, Filter, Reply};

pub mod delete;
pub mod ip;
pub mod login;
pub mod register;
pub mod validate;

pub fn routes() -> BoxedFilter<(impl Reply,)> {
    warp::path("api")
        .and(
            ip::route()
                .or(login::route())
                .or(register::route())
                .or(delete::route())
                .or(validate::route())
                .or(warp::path::end().map(|| {
                    warp::reply::with_status(
                        "I'm a teapot - never gonna give you up",
                        StatusCode::IM_A_TEAPOT,
                    )
                })),
        )
        .or(warp::fs::dir("./bundle"))
        .or(warp::fs::file("./bundle/index.html"))
        .boxed()
}
