use actix_web::{Responder, web};
use serde::{Deserialize, Serialize};

use crate::{
    database::blacklist::{get_collection, Blacklist}, authenticate::Authenticate, errors::{Error, Result},
};

#[derive(Deserialize, Serialize)]
pub struct LogoutResponse {
    success: bool,
}

pub async fn handle(jwt: web::ReqData<Result<Authenticate>>) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let blacklist = get_collection();
    let document = Blacklist { token: jwt.jwt };
    let result = blacklist.insert_one(document, None).await;
    if result.is_ok() {
        Ok(web::Json(LogoutResponse { success: true }))
    } else {
        Err(Error::DatabaseError)
    }
}
