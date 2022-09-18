use warp::reject::Rejection;
use warp::{wrap_fn, Filter};

pub fn with_cors<This, Reply>(
    this: This,
    origins: &'static [String],
) -> impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone
where
    This: Filter<Extract = (Reply,), Error = Rejection> + Send + Sync + 'static,
    This: Clone,
    Reply: Send + warp::Reply,
{
    let handle_headers = move |headers: warp::http::HeaderMap| async move {
        let origin = headers.get("Origin");
        if let Some(origin) = origin {
            let origin = origin.to_str().unwrap().to_string();
            if origins.contains(&origin) {
                Ok::<_, Rejection>(("Access-Control-Allow-Origin", origin))
            } else {
                Ok(("Access-Control-Allow-Origin", origins[0].to_string()))
            }
        } else {
            Ok(("Access-Control-Allow-Origin", "*".into()))
        }
    };

    this.with(wrap_fn::<_, This, _>(move |filter: This| {
        warp::header::headers_cloned()
            .and_then(handle_headers)
            .and(filter)
            .map(|header: (&'static str, String), reply: Reply| {
                warp::reply::with_header(reply, header.0, header.1)
            })
    }))
}
