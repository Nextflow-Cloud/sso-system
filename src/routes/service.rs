use actix_web::{web, Responder};
use serde::{Deserialize, Serialize};

use crate::constants::{SERVICE, VERSION};

#[derive(Deserialize, Serialize)]
pub struct ServiceResponse {
    pub service: &'static str,
    pub version: &'static str,
}

pub async fn handle() -> impl Responder {
    web::Json(ServiceResponse {
        service: SERVICE,
        version: VERSION,
    })
}
