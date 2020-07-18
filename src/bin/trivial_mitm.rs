use std::sync::Arc;
use async_trait::async_trait;

use argh::FromArgs;
use http::{Request, Response};

use third_wheel::*;

/// Run a TLS mitm proxy that does no modification to the traffic
#[derive(FromArgs)]
struct StartMitm {
    /// port to bind proxy to
    #[argh(option, short = 'p', default = "8080")]
    port: u16,
}

struct EmptyCapturer;
#[async_trait]
impl MitmLayer for EmptyCapturer {
    async fn capture_request(&self, _: &Request<Vec<u8>>) -> RequestCapture {
        RequestCapture::Continue
    }
    async fn capture_response(
        &self,
        _: &Request<Vec<u8>>,
        _: &Response<Vec<u8>>,
    ) -> ResponseCapture {
        ResponseCapture::Continue
    }
}

#[tokio::main]
async fn main() -> SafeResult {
    let args: StartMitm = argh::from_env();
    start_mitm(
        args.port,
        Arc::new(EmptyCapturer {}),
    )
        .await
}
