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

pub struct MitmLayer<T, S>
where
    T: Fn(&Request<Vec<u8>>) -> RequestCapture,
    S: Fn(&Request<Vec<u8>>, &Response<Vec<u8>>) -> ResponseCapture,
{
    pub request_capturer: T,
    pub response_capturer: S,
}

impl<T, S> MitmLayer<T, S>
where
    T: Fn(&Request<Vec<u8>>) -> RequestCapture,
    S: Fn(&Request<Vec<u8>>, &Response<Vec<u8>>) -> ResponseCapture,
{
    pub fn new(request_capturer: T, response_capturer: S) -> Self {
        Self { request_capturer, response_capturer }
    }
}
