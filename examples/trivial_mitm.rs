use std::{pin::Pin, sync::Arc};

use argh::FromArgs;
use futures::Future;
use http::{Request, Response};
use hyper::service::Service;

use hyper::Body;
use third_wheel::*;
use tokio::sync::Mutex;

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

#[derive(Clone)]
struct TrivialMitm {
    inner: Arc<Mutex<ThirdWheel>>,
}

#[derive(Clone)]
struct TrivialMakeMitm;

impl MakeMitm<TrivialMitm> for TrivialMakeMitm {
    fn new_mitm(&self, inner: ThirdWheel) -> TrivialMitm {
        TrivialMitm{ inner: Arc::new(Mutex::new(inner)) }
    }
}

impl Service<Request<Body>> for TrivialMitm {
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output=Result<Response<Body>, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        return if let Ok(mut third_wheel) = self.inner.try_lock() {
            third_wheel.poll_ready(cx)
        } else {
            std::task::Poll::Pending
        }
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let shared_sender = self.inner.clone();
        let fut = async move {
            let mut sender = shared_sender.lock().await;
            sender.call(req).await
        };
        return Box::pin(fut);
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: StartMitm = argh::from_env();
    let ca = CertificateAuthority::load_from_pem_files(&args.cert_file, &args.key_file)?;
    start_mitm(args.port, TrivialMakeMitm{}, ca).await
}
