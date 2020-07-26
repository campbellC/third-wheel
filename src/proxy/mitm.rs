use http::{Request, Response};
use async_trait::async_trait;

/// Action taken by `MitmLayer` on intercepting an outgoing request
pub enum RequestCapture {
    /// In the case the mitm should not send the request to the domain. Note the TLS handshake will have already taken place
    CircumventedResponse(Response<Vec<u8>>),
    /// This request will be sent in place of the client's original request
    ModifiedRequest(Request<Vec<u8>>),
    /// Use in the case the mitm should send the original request
    Continue,
}

/// Action taken by `MitmLayer` on intercepting an incoming response
pub enum ResponseCapture {
    /// This response will be sent to the client instead of the actual response from the server
    ModifiedResponse(Response<Vec<u8>>),
    /// Use in the case the mitm should not modify the original response
    Continue,
}

/// Capture requests and responses in flight, modify them, intercept them or whatever is required.
#[allow(clippy::module_name_repetitions)]
#[async_trait]
pub trait MitmLayer {
    async fn capture_request(&mut self, request: &Request<Vec<u8>>) -> RequestCapture;
    async fn capture_response(&mut self, request: &Request<Vec<u8>>, response: &Response<Vec<u8>>) -> ResponseCapture;
}
