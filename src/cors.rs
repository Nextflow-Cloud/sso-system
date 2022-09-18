// use warp::{Filter, Rejection, http, Reply};
// use crate::environment::CORS_ORIGINS;

// Allow CORS from any provided origin in the array.
// Sets the Access-Control-Allow-Origin header.
// pub async fn handle_headers(method: http::Method, headers: http::HeaderMap) -> Result<String, Rejection> {
//     let origin = headers.get("Origin").unwrap().to_str().unwrap();
//     if CORS_ORIGINS.contains(&origin) {
//         warp::reply::with_header(
//             warp::reply(),
//             "Access-Control-Allow-Origin",
//             origin,
//         )
//     } else {
//         warp::reply::with_header(
//             warp::reply(),
//             "Access-Control-Allow-Origin",
//             "https://www.example.com",
//         )
//     }
    
// }

#[macro_export]
macro_rules! cors {
    ($origins:expr) => {{
        use warp::wrap_fn;
        use warp::Filter;
        use warp::Future;
        use warp::Rejection;
        use warp::Reply;
        use std::pin::Pin;
        
        let handle_headers = |method: warp::http::Method, headers: warp::http::HeaderMap| async {
            let origin = headers.get("Origin");
            if let Some(origin) = origin {
                let origin = origin.to_str().unwrap();
                if $origins.contains(&origin.to_string()) {
                    Ok((
                        "Access-Control-Allow-Origin",
                        origin,
                    ))
                } else {
                    Ok((
                        "Access-Control-Allow-Origin",
                        $origins[0].as_str(),
                    ))
                }
            } else {
                Ok((
                    "Access-Control-Allow-Origin",
                    "*",
                ))
            }
        };

        wrap_fn(move |filter| {
            warp::method().and(warp::header::headers_cloned()).and_then(handle_headers).and(Box::new(filter) as Box<dyn Filter<Extract = (impl Reply,), Error = Rejection, Future = Pin<Box<dyn Future<Output = Result<(impl Reply, ), Rejection>> + Send>>>>).map(|header: (&str, &str), reply: Box<dyn warp::Reply>| {
                warp::reply::with_header(reply, header.0, header.1)
            })
            
        })
    }}
}
