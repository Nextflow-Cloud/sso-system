use actix_cors::Cors;
use actix_web::{HttpServer, App, middleware::Logger, web};

use crate::{environment::CORS_ORIGINS, authenticate::JwtAuthentication};

pub mod authenticate;
pub mod database;
pub mod environment;
pub mod routes;
pub mod utilities;
pub mod errors;

#[async_std::main]
async fn main() {
    database::connect().await;
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
            .route("/user", web::patch().to(routes::account_settings::handle))
            .route("/user", web::delete().to(routes::delete::handle))
            .route("/ip", web::get().to(routes::ip::handle))
            .route("/session", web::post().to(routes::login::handle))
            .route("/session", web::delete().to(routes::logout::handle))
            .route("/user", web::get().to(routes::current_user::handle))
            .route("/user/{id}", web::get().to(routes::user::handle))
            .route("/user/mfa", web::patch().to(routes::mfa::handle))
            .route("/validate", web::post().to(routes::validate::handle))
            // .route("/user/profile", routes::profile_settings::handle)
            // .route("/user/{id}", routes::user::handle)
            // .route("/user/{id}/register", routes::register::handle)

    })
    .bind("0.0.0.0:9000")
    .expect("Failed to start server")
    .run()
    .await
    .expect("Failed to start server");
}
