use http::{Request, Response, header::HeaderName};
use hyper::{Body, client::conn::{ResponseFuture, SendRequest}, service::Service};

/// A trait for a factory to produce new MITM layers. A new MITM will be produced per client-target pair
pub trait MakeMitm<T>
where
    T: Service<Request<Body>, Response = <ThirdWheel as Service<Request<Body>>>::Response>,
{
    fn new_mitm(&self, inner: ThirdWheel) -> T;
}

/// A service that will proxy traffic to a target server and return unmodified responses
pub struct ThirdWheel {
    inner: SendRequest<Body>,
}

impl ThirdWheel {
    pub(crate) fn new(inner: SendRequest<Body>) -> Self {
        Self { inner }
    }
}

impl Service<Request<Body>> for ThirdWheel {
    type Response = Response<Body>;

    type Error = hyper::Error;

    type Future = ResponseFuture;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    /// ThirdWheel performs very little modification of the request before
    /// transmitting it, but it does remove the proxy-connection header to
    /// ensure this is not passed to the target
    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        // TODO: remove unwraps
        // TODO: verify exactly what the behaviour *should* be - should we just pass through the request uri as is
        *request.uri_mut() = request
            .uri()
            .path_and_query()
            .unwrap()
            .as_str()
            .parse()
            .unwrap();
        // TODO: don't have this unnecessary overhead every time
        let proxy_connection: HeaderName = HeaderName::from_lowercase(b"proxy-connection")
            .expect("Infallible: hardcoded header name");
        request.headers_mut().remove(&proxy_connection);
        self.inner.send_request(request)
    }
}
