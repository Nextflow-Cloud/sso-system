use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use mongodb::bson::doc;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use warp::Rejection;

use crate::{environment::JWT_SECRET, routes::login::UserJwt};

pub struct Authenticate {
    pub(crate) jwt: String,
    pub(crate) jwt_content: UserJwt,
}

fn jwt_from_header(headers: &HeaderMap<HeaderValue>) -> Option<&str> {
    let header = match headers.get(AUTHORIZATION) {
        Some(v) => v,
        None => return None,
    };
    let auth_header = match std::str::from_utf8(header.as_bytes()) {
        Ok(v) => v,
        Err(_) => return None,
    };
    let bearer = "Bearer ";
    if !auth_header.starts_with(bearer) {
        return None;
    }
    Some(auth_header.trim_start_matches(bearer))
}

pub async fn authenticate(
    headers: HeaderMap<HeaderValue>,
) -> Result<Option<Authenticate>, Rejection> {
    let jwt = jwt_from_header(&headers);
    if let Some(j) = jwt {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims = HashSet::new();
        validation.validate_exp = false;
        let decoded = decode::<UserJwt>(
            j,
            &DecodingKey::from_secret(JWT_SECRET.as_ref()),
            &validation,
        );
        if let Ok(d) = decoded {
            let duration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Unexpected error: time went backwards");
            let millis = duration.as_millis();
            if millis > d.claims.expires_at {
                return Ok(None);
            }
            let collection = crate::database::blacklist::get_collection();
            let query = collection
                .find_one(
                    doc! {
                        "token": j
                    },
                    None,
                )
                .await;
            if let Ok(q) = query {
                if q.is_some() {
                    return Ok(None);
                }
            }
            let value = Authenticate {
                jwt: j.to_string(),
                jwt_content: d.claims,
            };
            Ok(Some(value))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}
