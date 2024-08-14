use actix_web::{
    web::{self, Json},
    Responder,
};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{authenticate::Authenticate, database::session::get_collection, errors::Result};
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutOther {
    id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutOtherResponse {
    success: bool,
}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
    logout_other: Json<LogoutOther>,
) -> Result<impl Responder> {
    jwt.into_inner()?;
    let sessions = get_collection();
    sessions.delete_one(doc! { "id": &logout_other.id }).await?;
    Ok(web::Json(LogoutOtherResponse { success: true }))
}
