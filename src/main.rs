use warp::Filter;

pub mod authenticate;
pub mod database;
pub mod email;
pub mod environment;
pub mod routes;
pub mod utilities;

#[async_std::main]
async fn main() {
    database::connect().await;
    warp::serve(routes::routes()
        .with(warp::cors().allow_origins(environment::CORS_ORIGINS.iter().map(|s| s.as_str()))))
        .run(([0, 0, 0, 0], 9000))
        .await;
}
