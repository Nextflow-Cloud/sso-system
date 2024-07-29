use actix_web::{web, Responder};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{
    authenticate::Authenticate,
    database::session::get_collection,
    errors::Result,
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutResponse {
    success: bool,
}

pub async fn handle(jwt: web::ReqData<Result<Authenticate>>) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let sessions = get_collection();
    sessions.delete_one(doc! { "token": jwt.jwt }, None).await?;
    Ok(web::Json(LogoutResponse { success: true }))
}
