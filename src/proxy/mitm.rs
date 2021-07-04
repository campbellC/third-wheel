use std::pin::Pin;

use crate::error::Error;
use futures::Future;
use http::{header::HeaderName, Request, Response};
use hyper::{client::conn::SendRequest, service::Service, Body};
use log::error;
use tokio::sync::{mpsc, oneshot};
use tower::Layer;

type ResponseSender = oneshot::Sender<Result<Response<Body>, Error>>;

pub(crate) struct RequestSendingSynchronizer {
    request_sender: SendRequest<Body>,
    receiver: mpsc::UnboundedReceiver<(ResponseSender, Request<Body>)>,
}

impl RequestSendingSynchronizer {
    pub(crate) const fn new(
        request_sender: SendRequest<Body>,
        receiver: mpsc::UnboundedReceiver<(ResponseSender, Request<Body>)>,
    ) -> Self {
        Self {
            request_sender,
            receiver,
        }
    }

    pub(crate) async fn run(&mut self) {
        while let Some((sender, mut request)) = self.receiver.recv().await {
            let relativized_uri = request
                .uri()
                .path_and_query()
                .ok_or_else(|| Error::RequestError("URI did not contain a path".to_string()))
                .and_then(|path| {
                    path.as_str()
                        .parse()
                        .map_err(|_| Error::RequestError("Given URI was invalid".to_string()))
                });
            let response_fut = relativized_uri.map(|path| {
                *request.uri_mut() = path;
                // TODO: don't have this unnecessary overhead every time
                let proxy_connection: HeaderName = HeaderName::from_lowercase(b"proxy-connection")
                    .expect("Infallible: hardcoded header name");
                request.headers_mut().remove(&proxy_connection);
                self.request_sender.send_request(request)
            });
            let response_to_send = match response_fut {
                Ok(response) => response.await.map_err(|e| e.into()),
                Err(e) => Err(e),
            };
            if let Err(e) = sender.send(response_to_send) {
                error!("Requester not available to receive request {:?}", e);
            }
        }
    }
}

/// A service that will proxy traffic to a target server and return unmodified responses
#[derive(Clone)]
pub struct ThirdWheel {
    sender: mpsc::UnboundedSender<(ResponseSender, Request<Body>)>,
}

impl ThirdWheel {
    pub(crate) const fn new(
        sender: mpsc::UnboundedSender<(ResponseSender, Request<Body>)>,
    ) -> Self {
        Self { sender }
    }
}

impl Service<Request<Body>> for ThirdWheel {
    type Response = Response<Body>;

    type Error = crate::error::Error;

    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    /// `ThirdWheel` performs very little modification of the request before
    /// transmitting it, but it does remove the proxy-connection header to
    /// ensure this is not passed to the target
    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let (response_sender, response_receiver) = oneshot::channel();
        let sender = self.sender.clone();
        let fut = async move {
            //TODO: clarify what errors are possible here
            sender.send((response_sender, request)).map_err(|_| {
                Error::ServerError("Failed to connect to server correctly".to_string())
            })?;
            response_receiver
                .await
                .map_err(|_| Error::ServerError("Failed to get response from server".to_string()))?
        };
        Box::pin(fut)
    }
}

#[derive(Clone)]
pub struct MitmService<F: Clone, S: Clone> {
    f: F,
    inner: S,
}

impl<F, S> Service<Request<Body>> for MitmService<F, S>
where
    S: Service<Request<Body>, Error = crate::error::Error> + Clone,
    F: FnMut(
            Request<Body>,
            S,
        )
            -> Pin<Box<dyn Future<Output = Result<Response<Body>, crate::error::Error>> + Send>>
        + Clone,
{
    type Response = Response<Body>;
    type Error = crate::error::Error;

    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        (self.f)(req, self.inner.clone())
    }
}

#[derive(Clone)]
pub struct MitmLayer<F: Clone> {
    f: F,
}

impl<S: Clone, F: Clone> Layer<S> for MitmLayer<F> {
    type Service = MitmService<F, S>;
    fn layer(&self, inner: S) -> Self::Service {
        MitmService {
            f: self.f.clone(),
            inner,
        }
    }
}

/// A convenience function for generating man-in-the-middle services
///
/// This function generates a struct that implements the necessary traits to be
/// used as a man-in-the-middle service and will suffice for many use cases.
/// ```ignore
/// let mitm = mitm_layer(|req: Request<Body>, mut third_wheel: ThirdWheel| third_wheel.call(req));
/// let mitm_proxy = MitmProxy::builder(mitm, ca).build();
/// ```
pub fn mitm_layer<F>(f: F) -> MitmLayer<F>
where
    F: FnMut(
            Request<Body>,
            ThirdWheel,
        )
            -> Pin<Box<dyn Future<Output = Result<Response<Body>, crate::error::Error>> + Send>>
        + Clone,
{
    MitmLayer { f }
}
