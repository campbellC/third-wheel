use http::{Request, Response};
use async_trait::async_trait;

pub enum RequestCapture {
    CircumventedResponse(Response<Vec<u8>>),
    ModifiedRequest(Request<Vec<u8>>),
    Continue,
}

pub enum ResponseCapture {
    ModifiedResponse(Response<Vec<u8>>),
    Continue,
}

#[allow(clippy::module_name_repetitions)]
#[async_trait]
pub trait MitmLayer {
    async fn capture_request(&self, request: &Request<Vec<u8>>) -> RequestCapture;
    async fn capture_response(&self, request: &Request<Vec<u8>>, response: &Response<Vec<u8>>) -> ResponseCapture;
}
