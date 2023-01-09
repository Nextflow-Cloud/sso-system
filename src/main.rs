use std::time::Duration;

use actix_cors::Cors;
use actix_extensible_rate_limit::{
    backend::{memory::InMemoryBackend, SimpleInputFunctionBuilder},
    RateLimiter,
};
use actix_files::Files;
use actix_web::{middleware::Logger, web, App, HttpServer};
use async_std::task;
use log::info;

use crate::{
    authenticate::JwtAuthentication,
    environment::{CORS_ORIGINS, HOST},
};

pub mod authenticate;
pub mod cleanup;
pub mod database;
pub mod environment;
pub mod errors;
pub mod routes;
pub mod utilities;

#[async_std::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    info!("Nextflow SSO system version {}", env!("CARGO_PKG_VERSION"));
    info!("Connecting to MongoDB...");
    database::connect().await;

    info!("Spawning task to clean up expired entities...");
    task::spawn(async {
        loop {
            task::sleep(std::time::Duration::from_secs(60)).await;
            task::spawn(async { cleanup::run() });
        }
    });
    
    info!("Starting server on {}...", *HOST);
    HttpServer::new(|| {
        let backend = InMemoryBackend::builder().build();
        let input = SimpleInputFunctionBuilder::new(Duration::from_secs(5), 3)
            .real_ip_key()
            .build();
        App::new()
            .wrap(
                Cors::default()
                    .allowed_origin_fn(|_, head| {
                        head.headers
                            .get("origin")
                            .and_then(|origin| {
                                let origin = origin.to_str().ok()?;
                                if CORS_ORIGINS.contains(&origin.to_string()) {
                                    Some(origin)
                                } else {
                                    None
                                }
                            })
                            .is_some()
                    })
                    .allow_any_method()
                    .allow_any_header()
                    .supports_credentials(),
            )
            .wrap(Logger::default())
            .service(Files::new("/bundle", "bundle"))
            .service(
                web::scope("/api")
            .wrap(RateLimiter::builder(backend, input).add_headers().build())
            .wrap(JwtAuthentication)
            .route("/user", web::patch().to(routes::account_settings::handle))
            .route("/user", web::get().to(routes::current_user::handle))
            .route("/user", web::delete().to(routes::delete::handle))
            .route("/ip", web::get().to(routes::ip::handle))
            .route("/session", web::post().to(routes::login::handle))
            .route("/session", web::delete().to(routes::logout::handle))
            .route("/user/mfa", web::patch().to(routes::mfa::handle))
            .route("/user", web::post().to(routes::register::handle))
            .route("/user/{id}", web::get().to(routes::user::handle))
            .route("/validate", web::post().to(routes::validate::handle))
            .route(
                "/user/profile",
                web::patch().to(routes::profile_settings::handle),
                    ),
            )
    })
    .bind(HOST.clone())
    .expect("Failed to start server")
    .run()
    .await
    .expect("Failed to start server");
}
