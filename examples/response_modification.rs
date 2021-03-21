use argh::FromArgs;
use http::{Request, Response};

use hyper::Body;
use third_wheel::*;

/// Run a TLS mitm proxy that does modifies all responses to be a given string
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

    /// string to return for any request
    #[argh(option, short = 'r', default = "\"Hello, World!\".to_string()")]
    modified_response: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: StartMitm = argh::from_env();
    let ca = CertificateAuthority::load_from_pem_files_with_passphrase_on_key(
        &args.cert_file,
        &args.key_file,
        "third-wheel",
    )?;

    let modified_response = args.modified_response.clone();
    let modifying_mitm = mitm_layer(move |_: Request<Body>, _: ThirdWheel| {
        Box::pin(std::future::ready(Ok(Response::builder()
            .body(Body::from(modified_response.clone()))
            .unwrap())))
    });
    let mitm_proxy = MitmProxy::builder(modifying_mitm, ca).build();
    let (_, mitm_proxy_fut) = mitm_proxy.bind(format!("127.0.0.1:{}", args.port).parse().unwrap());
    mitm_proxy_fut.await.unwrap();
    Ok(())
}
