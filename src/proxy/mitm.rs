use async_trait::async_trait;
use http::{Request, Response};

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
    async fn capture_request(&self, request: &Request<Vec<u8>>) -> RequestCapture;
    async fn capture_response(
        &self,
        request: &Request<Vec<u8>>,
        response: &Response<Vec<u8>>,
    ) -> ResponseCapture;
}

/// Quality of life macro to wrap `MitmLayer`'s in an Arc.
///
/// Since `MitmLayer`'s need to be shared between threads, it's common to wrap them in an Arc.
/// The Orphan rules make this verbose with boiler plate so this macro does that lifting for you.
/// Just define a struct that implements `MitmLayer` and then call `wrap_mitm_in_arc!` on an instance
/// and it will define a new struct that can be passed into the mitm proxy functions by wrapping it in an Arc.
/// See the examples for both immutable and mutable use cases.

#[macro_export]
macro_rules! wrap_mitm_in_arc {
    ($e:expr) => {{
        use http::{Request, Response};
        use std::ops::Deref;
        use std::sync::Arc;
        struct _ThirdWheelWrapper<T: MitmLayer + Send + Sync>(Arc<T>);

        impl<T: MitmLayer + Send + Sync> Clone for _ThirdWheelWrapper<T> {
            fn clone(&self) -> Self {
                _ThirdWheelWrapper {
                    0: Arc::clone(&self.0),
                }
            }
        }

        impl<T: MitmLayer + Send + Sync> Deref for _ThirdWheelWrapper<T> {
            type Target = Arc<T>;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        #[async_trait]
        impl<T: MitmLayer + Send + Sync> MitmLayer for _ThirdWheelWrapper<T> {
            async fn capture_request(&self, request: &Request<Vec<u8>>) -> RequestCapture {
                self.0.capture_request(request).await
            }
            async fn capture_response(
                &self,
                request: &Request<Vec<u8>>,
                response: &Response<Vec<u8>>,
            ) -> ResponseCapture {
                self.0.capture_response(request, response).await
            }
        }
        _ThirdWheelWrapper { 0: Arc::new($e) }
    }};
}
