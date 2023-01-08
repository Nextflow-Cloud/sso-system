use actix_cors::Cors;
use actix_files::Files;
use actix_web::{HttpServer, App, middleware::Logger, web};
use async_std::task;
use log::info;

use crate::{environment::{CORS_ORIGINS, HOST}, authenticate::JwtAuthentication};

pub mod authenticate;
pub mod database;
pub mod environment;
pub mod routes;
pub mod utilities;
pub mod errors;
pub mod cleanup;

#[async_std::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    info!("Nextflow SSO system version {}", env!("CARGO_PKG_VERSION"));
    info!("Connecting to MongoDB...");
    database::connect().await;

    info!("Spawning task to clean up expired entities...");
    task::spawn(async {
        loop {
            task::spawn(async { cleanup::run() });
            task::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
    
    info!("Starting server on {}...", *HOST);
    HttpServer::new(|| {
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
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(["Authorization", "Accept", "Content-Type"])
                    .supports_credentials(),
            )
            .wrap(JwtAuthentication)
            .wrap(Logger::default())
            .service(Files::new("/bundle", "bundle"))
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
            .route("/user/profile", web::patch().to(routes::profile_settings::handle))
    })
    .bind(HOST.clone())
    .expect("Failed to start server")
    .run()
    .await
    .expect("Failed to start server");
}
