use warp::{filters::BoxedFilter, hyper::StatusCode, Filter, Reply};

pub mod login;
pub mod register;
pub mod validate;
pub mod delete;

pub fn routes() -> BoxedFilter<(impl Reply,)> {
    login::route()
    .or(register::route())
    .or(validate::route())
    .or(warp::path("api").map(|| {
        warp::reply::with_status(
            "I'm a teapot - never gonna give you up",
            StatusCode::IM_A_TEAPOT,
        )
    }))
    .or(warp::fs::dir("./bundle"))
    .or(warp::fs::file("./bundle/index.html"))
    .boxed()
}
