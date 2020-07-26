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

    /// pem file for self-signed certificate authority certificate
    #[argh(option, short = 'c', default = "\"ca/ca_certs/cert.pem\".to_string()")]
    cert_file: String,

    /// pem file for private signing key for the certificate authority
    #[argh(option, short = 'k', default = "\"ca/ca_certs/key.pem\".to_string()")]
    key_file: String,
}

struct EmptyCapturer;
// Since this is the same crate we can actually impl MitmLayer for
// Arc<EmptyCapturer> directly. However, since this code should also be an
// example of how to use the library we wrap in a struct to show how to avoid
// the orphan rules
struct WrapperStruct (Arc<EmptyCapturer>);

impl Clone for WrapperStruct {
    fn clone(&self) -> Self {
        WrapperStruct {0: Arc::clone(&self.0)}
    }
}

#[async_trait]
impl MitmLayer for WrapperStruct {
    async fn capture_request(&mut self, _: &Request<Vec<u8>>) -> RequestCapture {
        RequestCapture::Continue
    }
    async fn capture_response(
        &mut self,
        _: &Request<Vec<u8>>,
        _: &Response<Vec<u8>>,
    ) -> ResponseCapture {
        ResponseCapture::Continue
    }
}

#[tokio::main]
async fn main() -> SafeResult {
    let args: StartMitm = argh::from_env();
    let ca = CertificateAuthority::load_from_pem_files(&args.cert_file, &args.key_file)?;
    start_mitm(
        args.port,
        WrapperStruct {0: Arc::new(EmptyCapturer {})},
        ca,
    )
        .await
}
