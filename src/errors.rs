use std::fmt::Display;

use actix_web::ResponseError;
use log::error;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "error", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Error {
    MissingToken,
    InvalidToken,

    DatabaseError,

    InvalidUsername,
    UsernameAlreadyTaken,
    UserNotFound,
    UserExists,

    MissingEmail,
    InvalidEmail,
    MissingPassword,
    MissingCode,
    DisplayNameTooLong,
    DescriptionTooLong,
    WebsiteTooLong,

    IncorrectCredentials,
    IncorrectCode,

    MissingContinueToken,
    SessionExpired,
    InvalidStage,

    IpMissing,

    InvalidCaptcha,
    InternalCaptchaError,

    InternalEmailError,
    EmailMisconfigured,

    RateLimited {
        limit: u64,
        remaining: u64,
        reset: u64,
    },
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}

impl ResponseError for Error {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            Error::MissingToken => actix_web::http::StatusCode::UNAUTHORIZED,
            Error::InvalidToken => actix_web::http::StatusCode::UNAUTHORIZED,

            Error::DatabaseError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,

            Error::InvalidUsername => actix_web::http::StatusCode::BAD_REQUEST,
            Error::UsernameAlreadyTaken => actix_web::http::StatusCode::CONFLICT,
            Error::UserNotFound => actix_web::http::StatusCode::NOT_FOUND,
            Error::UserExists => actix_web::http::StatusCode::CONFLICT,

            Error::MissingEmail => actix_web::http::StatusCode::BAD_REQUEST,
            Error::InvalidEmail => actix_web::http::StatusCode::BAD_REQUEST,
            Error::MissingPassword => actix_web::http::StatusCode::BAD_REQUEST,
            Error::MissingCode => actix_web::http::StatusCode::BAD_REQUEST,
            Error::DisplayNameTooLong => actix_web::http::StatusCode::BAD_REQUEST,
            Error::DescriptionTooLong => actix_web::http::StatusCode::BAD_REQUEST,
            Error::WebsiteTooLong => actix_web::http::StatusCode::BAD_REQUEST,

            Error::IncorrectCredentials => actix_web::http::StatusCode::UNAUTHORIZED,
            Error::IncorrectCode => actix_web::http::StatusCode::UNAUTHORIZED,

            Error::MissingContinueToken => actix_web::http::StatusCode::BAD_REQUEST,
            Error::SessionExpired => actix_web::http::StatusCode::UNAUTHORIZED,
            Error::InvalidStage => actix_web::http::StatusCode::BAD_REQUEST,

            Error::IpMissing => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,

            Error::InvalidCaptcha => actix_web::http::StatusCode::BAD_REQUEST,
            Error::InternalCaptchaError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,

            Error::RateLimited { .. } => actix_web::http::StatusCode::TOO_MANY_REQUESTS,

            Error::InternalEmailError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::EmailMisconfigured => actix_web::http::StatusCode::METHOD_NOT_ALLOWED,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse {
        actix_web::HttpResponse::build(self.status_code()).json(self)
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(_: jsonwebtoken::errors::Error) -> Self {
        Error::InvalidToken
    }
}

impl From<mongodb::error::Error> for Error {
    fn from(db: mongodb::error::Error) -> Self {
        error!("Database error: {}", db);
        Error::DatabaseError
    }
}

pub type Result<T> = std::result::Result<T, Error>;
