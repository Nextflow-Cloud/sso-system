use actix_web::{web, HttpRequest, Responder};
use serde::{Deserialize, Serialize};

use crate::errors::{Error, Result};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpResponse {
    ip: String,
}

pub async fn handle(req: HttpRequest) -> Result<impl Responder> {
    let connection_info = req.connection_info();
    let ip = connection_info
        .realip_remote_addr()
        .ok_or(Error::IpMissing)?;
    Ok(web::Json(IpResponse { ip: ip.to_string() }))
}
