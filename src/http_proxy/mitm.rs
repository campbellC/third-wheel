use http::{Request, Response};

pub enum RequestCapture {
    CircumventedResponse(Response<Vec<u8>>),
    ModifiedRequest(Request<Vec<u8>>),
    Continue,
}

pub enum ResponseCapture {
    ModifiedResponse(Response<Vec<u8>>),
    Continue,
}

pub trait MitmLayer {
    fn capture_request(&self, request: &Request<Vec<u8>>) -> RequestCapture;
    fn capture_response(&self, request: &Request<Vec<u8>>, response: &Response<Vec<u8>>) -> ResponseCapture;
}
