use std::pin::Pin;

use crate::error::Error;
use futures::Future;
use http::{header::HeaderName, Request, Response};
use hyper::{client::conn::SendRequest, service::Service, Body};
use log::error;
use tokio::sync::{mpsc, oneshot};

/// A trait for a factory to produce new MITM layers. A new MITM will be produced per client-target pair
pub trait MakeMitm<T>
where
    T: Service<Request<Body>, Response = <ThirdWheel as Service<Request<Body>>>::Response>,
{
    fn new_mitm(&self, inner: ThirdWheel) -> T;
}

pub(crate) struct RequestSendingSynchronizer {
    request_sender: SendRequest<Body>,
    receiver: mpsc::UnboundedReceiver<(
        oneshot::Sender<Result<Response<Body>, Error>>,
        Request<Body>,
    )>,
}

impl RequestSendingSynchronizer {
    pub(crate) fn new(
        request_sender: SendRequest<Body>,
        receiver: mpsc::UnboundedReceiver<(
            oneshot::Sender<Result<Response<Body>, Error>>,
            Request<Body>,
        )>,
    ) -> Self {
        Self {
            request_sender,
            receiver,
        }
    }

    pub(crate) async fn run(&mut self) {
        while let Some((sender, mut request)) = self.receiver.recv().await {
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
            let response = self.request_sender.send_request(request);
            if let Err(e) = sender.send(response.await.map_err(|e| e.into())) {
                error!("Requester not available to receive request {:?}", e);
            }
        }
    }
}

/// A service that will proxy traffic to a target server and return unmodified responses
#[derive(Clone)]
pub struct ThirdWheel {
    sender: mpsc::UnboundedSender<(
        oneshot::Sender<Result<Response<Body>, Error>>,
        Request<Body>,
    )>,
}

impl ThirdWheel {
    pub(crate) fn new(
        sender: mpsc::UnboundedSender<(
            oneshot::Sender<Result<Response<Body>, Error>>,
            Request<Body>,
        )>,
    ) -> Self {
        Self { sender }
    }
}

impl Service<Request<Body>> for ThirdWheel {
    type Response = Response<Body>;

    type Error = crate::error::Error;

    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    /// ThirdWheel performs very little modification of the request before
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
        return Box::pin(fut);
    }
}
