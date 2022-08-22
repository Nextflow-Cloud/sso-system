// use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use warp::Rejection;

use crate::{environment::JWT_SECRET, routes::login::UserJwt};

pub struct Authenticate {
    pub(crate) jwt: String,
    pub(crate) jwt_content: UserJwt,
}

fn jwt_from_header(headers: &HeaderMap<HeaderValue>) -> Option<String> {
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
    Some(auth_header.trim_start_matches(bearer).to_owned())
}

pub async fn authenticate(
    headers: HeaderMap<HeaderValue>,
) -> Result<Option<Authenticate>, Rejection> {
    let jwt = jwt_from_header(&headers);
    if let Some(j) = jwt {
        let decoded = decode::<UserJwt>(
            &j,
            &DecodingKey::from_secret(JWT_SECRET.as_ref()),
            &Validation::new(Algorithm::HS512),
        );
        if let Ok(d) = decoded {
            let value = Authenticate {
                jwt: j,
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
