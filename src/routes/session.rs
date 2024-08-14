use actix_web::{web, Responder};
use futures_util::StreamExt;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::authenticate::Authenticate;
use crate::database::session::{self, Session};
use crate::errors::Result;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSession {
    id: String,
    friendly_name: String,
}

pub async fn handle(
    user_id: web::Path<String>,
    jwt: web::ReqData<Result<Authenticate>>,
) -> Result<impl Responder> {
    jwt.into_inner()?;
    let sessions = session::get_collection();
    let result = sessions
        .find(doc! {
            "user_id": user_id.clone()
        })
        .await?
        .collect::<Vec<std::result::Result<Session, _>>>()
        .await
        .into_iter()
        .collect::<std::result::Result<Vec<Session>, _>>()?;
    
    let result = result
        .into_iter()
        .map(|session| ClientSession {
            id: session.id,
            friendly_name: session.friendly_name,
        })
        .collect::<Vec<ClientSession>>();

    Ok(web::Json(result))
}
