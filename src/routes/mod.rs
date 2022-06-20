use warp::{filters::BoxedFilter, hyper::StatusCode, Filter, Reply};

pub mod login;

pub fn routes() -> BoxedFilter<(impl Reply,)> {
    warp::path::end().map(|| {
        warp::reply::with_status(
            "I'm a teapot - never gonna give you up",
            StatusCode::IM_A_TEAPOT,
        )
    }).or(login::route()).boxed()
}
