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
async fn main() -> Result<(), Error> {
    let args: StartMitm = argh::from_env();
    let ca = CertificateAuthority::load_from_pem_files(&args.cert_file, &args.key_file)?;
    start_mitm(args.port, wrap_mitm_in_arc!(EmptyCapturer {}), ca).await
}
