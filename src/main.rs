pub mod authenticate;
pub mod cors;
pub mod database;
pub mod environment;
pub mod routes;
pub mod utilities;

#[async_std::main]
async fn main() {
    database::connect().await;
    warp::serve(cors::with_cors(
        routes::routes(),
        &environment::CORS_ORIGINS,
    ))
    .run(([0, 0, 0, 0], 9000))
    .await;
}
