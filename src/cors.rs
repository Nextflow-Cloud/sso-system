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
                Ok::<_, Rejection>(origin)
            } else {
                Ok(origins[0].to_string())
            }
        } else {
            Ok("*".into())
        }
    };

    this.with(wrap_fn::<_, This, _>(move |filter: This| {
        warp::header::headers_cloned()
            .and_then(handle_headers)
            .and(filter)
            .map(|header: String, reply: Reply| {
                let allow_origin =
                    warp::reply::with_header(reply, "Access-Control-Allow-Origin", header);
                let allow_headers =
                    warp::reply::with_header(allow_origin, "Access-Control-Allow-Headers", "*");
                warp::reply::with_header(allow_headers, "Access-Control-Allow-Methods", "*")
            })
    }))
}
