use futures::Future;
use futures::FutureExt;
use hyper::server::conn::Http;
use hyper::{client::conn::Builder, service::Service};
use native_tls::Certificate;
use openssl::x509::X509;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tower::Layer;

use http::{Request, Response};

use tokio_native_tls::{TlsAcceptor, TlsStream};

use crate::certificates::spoof_certificate;
use crate::error::Error;

use log::error;

use crate::{
    certificates::{native_identity, CertificateAuthority},
    proxy::mitm::ThirdWheel,
};
use hyper::service::{make_service_fn, service_fn};
use hyper::{server::Server, Body};

use self::mitm::RequestSendingSynchronizer;

pub(crate) mod mitm;

// TODO: do this without macro hackery
// The idea of using of a macro here is borrowed from warp after hitting my head against it for some time.
// We want to be able to return a make service for reuse of code. But the return
// type is inordinately complex and/or hidden by hyper's module privacy so instead we inline the code twice.
// either we should replace this with a private function on MitmProxy, or we should do *something else*
macro_rules! make_service {
    ($this:ident) => {{
        let ca = Arc::new($this.ca);
        let mitm = $this.mitm_layer;
        let additional_host_mapping = $this.additional_host_mappings;
        let additional_root_certificates = $this.additional_root_certificates;
        make_service_fn(move |_| {
            // While the state was moved into the make_service closure,
            // we need to clone it here because this closure is called
            // once for every connection.
            //
            // Each connection could send multiple requests, so
            // the `Service` needs a clone to handle later requests.
            let ca = ca.clone();
            let mitm = mitm.clone();
            let additional_host_mapping = additional_host_mapping.clone();
            let additional_root_certificates = additional_root_certificates.clone();

            async move {
                Ok::<_, Error>(service_fn(move |mut req: Request<Body>| {
                    log::info!("Received request to connect: {}", req.uri());
                    let mut res = Response::new(Body::empty());

                    // The proxy can only handle CONNECT requests
                    if req.method() == http::Method::CONNECT {
                        let target = target_host_port_from_connect(&req);
                        match target {
                            Ok((host, port)) => {
                                // TODO: handle non-encrypted proxying
                                // TODO: how to handle port != 80/443
                                // In the case of a TLS tunnel request we spawn a new
                                // service to handle the upgrade. This will only happen
                                // after the currently running function finishes so we need
                                // to spawn it as a separate future.
                                let ca = ca.clone();
                                let mitm = mitm.clone();
                                let additional_host_mapping = additional_host_mapping.clone();
                                let additional_root_certificates =
                                    additional_root_certificates.clone();
                                tokio::task::spawn(async move {
                                    match hyper::upgrade::on(&mut req).await {
                                        Ok(upgraded) => {
                                            if let Err(e) = run_mitm_on_connection(
                                                upgraded,
                                                ca,
                                                &host,
                                                &port,
                                                mitm,
                                                additional_host_mapping.clone(),
                                                additional_root_certificates.clone(),
                                            )
                                            .await
                                            {
                                                error!("Proxy failed: {}", e)
                                            }
                                        }
                                        Err(e) => error!("Failed to upgrade to TLS: {}", e),
                                    }
                                });
                                *res.status_mut() = http::status::StatusCode::OK;
                            }

                            Err(e) => {
                                error!(
                                    "Bad request: unable to parse host from connect request: {}",
                                    e
                                );
                                *res.status_mut() = http::status::StatusCode::BAD_REQUEST;
                            }
                        }
                    } else {
                        *res.status_mut() = http::status::StatusCode::BAD_REQUEST;
                    }
                    async move { Ok::<_, Error>(res) }
                }))
            }
        })
    }};
}

/// The main struct of the crate. Start here.
///
/// This struct is the workhorse and main interface for third-wheel.
/// By passing in a Mitm layer this can be customized to perform any required
/// behavior on HTTP requests and responses. Use the `mitm_layer` function to
/// easily construct services to pass in to this struct.
pub struct MitmProxy<T, U>
where
    T: Layer<ThirdWheel, Service = U> + Sync + std::marker::Send + 'static + Clone,
    U: Service<Request<Body>, Response = <ThirdWheel as Service<Request<Body>>>::Response>
        + Sync
        + Send
        + Clone
        + 'static,
    <U as Service<Request<Body>>>::Future: Send,
    <U as Service<Request<Body>>>::Error: std::error::Error + Send + Sync + 'static,
{
    mitm_layer: T,
    ca: CertificateAuthority,
    additional_root_certificates: Vec<Certificate>,
    additional_host_mappings: HashMap<String, String>, // TODO: this should be more restrictively typed
}

/// Builder interface for constructing `MitmProxy`'s
pub struct MitmProxyBuilder<T, U>
where
    T: Layer<ThirdWheel, Service = U> + Sync + std::marker::Send + 'static + Clone,
    U: Service<Request<Body>, Response = <ThirdWheel as Service<Request<Body>>>::Response>
        + Sync
        + Send
        + Clone
        + 'static,
    <U as Service<Request<Body>>>::Future: Send,
    <U as Service<Request<Body>>>::Error: std::error::Error + Send + Sync + 'static,
{
    mitm_layer: T,
    ca: CertificateAuthority,
    additional_root_certificates: Vec<Certificate>,
    additional_host_mappings: HashMap<String, String>,
}

// impl MitmProxyBuilder
impl<T, U> MitmProxyBuilder<T, U>
where
    T: Layer<ThirdWheel, Service = U> + Sync + std::marker::Send + 'static + Clone,
    U: Service<Request<Body>, Response = <ThirdWheel as Service<Request<Body>>>::Response>
        + Sync
        + Send
        + Clone
        + 'static,
    <U as Service<Request<Body>>>::Future: Send,
    <U as Service<Request<Body>>>::Error: std::error::Error + Send + Sync + 'static,
{
    pub fn build(self) -> MitmProxy<T, U> {
        MitmProxy {
            mitm_layer: self.mitm_layer,
            ca: self.ca,
            additional_root_certificates: self.additional_root_certificates,
            additional_host_mappings: self.additional_host_mappings,
        }
    }

    /// Add root certificates that the proxy should trust when making outgoing
    /// connections. This is in addition to the system certificates that are
    /// already trusted.
    pub fn additional_root_certificates(
        mut self,
        additional_root_certificates: Vec<Certificate>,
    ) -> Self {
        self.additional_root_certificates = additional_root_certificates;
        self
    }

    /// Add mappings for particular hosts to IP addresses. Useful for testing against local TLS servers.
    pub fn additional_host_mappings(
        mut self,
        additional_host_mappings: HashMap<String, String>,
    ) -> Self {
        self.additional_host_mappings = additional_host_mappings;
        self
    }
}

// impl MitmProxy
impl<T, U> MitmProxy<T, U>
where
    T: Layer<ThirdWheel, Service = U> + Sync + std::marker::Send + 'static + Clone,
    U: Service<Request<Body>, Response = <ThirdWheel as Service<Request<Body>>>::Response>
        + Sync
        + Send
        + Clone
        + 'static,
    <U as Service<Request<Body>>>::Future: Send,
    <U as Service<Request<Body>>>::Error: std::error::Error + Send + Sync + 'static,
{
    pub fn builder(mitm_layer: T, ca: CertificateAuthority) -> MitmProxyBuilder<T, U> {
        MitmProxyBuilder {
            mitm_layer,
            ca,
            additional_root_certificates: Vec::new(),
            additional_host_mappings: HashMap::new(),
        }
    }

    /// Bind to a socket address. Returns the address actually bound to, and the
    /// future to be executed that will run the server.
    pub fn bind(self, addr: SocketAddr) -> (SocketAddr, impl Future<Output = Result<(), Error>>) {
        let server = Server::bind(&addr).serve(make_service!(self));
        (
            server.local_addr(),
            server.map(|result| result.map_err(|e| e.into())),
        )
    }

    /// The same as bind except in the event that signal completes the proxy
    /// will gracefully terminate itself.
    /// ```ignore
    /// let trivial_mitm = MitmProxy::builder(
    ///     mitm_layer(|req: Request<Body>, mut third_wheel: ThirdWheel| third_wheel.call(req)),
    ///     third_wheel_ca,
    /// ).build();

    /// let (third_wheel_killer, receiver) = tokio::sync::oneshot::channel();
    /// let (third_wheel_address, mitm_fut) = trivial_mitm
    ///     .bind_with_graceful_shutdown("127.0.0.1:0".parse().unwrap(), async {
    ///         receiver.await.ok().unwrap()
    ///     });
    /// tokio::spawn(mitm_fut);
    /// // Wait for some stuff to happen
    /// third_wheel_killer.send(()).unwrap();
    /// // This kills the proxy
    /// ```
    pub fn bind_with_graceful_shutdown<F>(
        self,
        addr: SocketAddr,
        signal: F,
    ) -> (SocketAddr, impl Future<Output = Result<(), Error>>)
    where
        F: Future<Output = ()>,
    {
        let server = Server::bind(&addr).serve(make_service!(self));
        (
            server.local_addr(),
            server
                .with_graceful_shutdown(signal)
                .map(|result| result.map_err(|e| e.into())),
        )
    }
}

async fn run_mitm_on_connection<S, T, U>(
    upgraded: S,
    ca: Arc<CertificateAuthority>,
    host: &str,
    port: &str,
    mitm_maker: T,
    additional_host_mapping: HashMap<String, String>,
    additional_root_certificates: Vec<Certificate>,
) -> Result<(), Error>
where
    T: Layer<ThirdWheel, Service = U> + Sync + std::marker::Send + 'static + Clone,
    S: AsyncRead + AsyncWrite + Unpin + 'static + Send,
    U: Service<Request<Body>, Response = <ThirdWheel as Service<Request<Body>>>::Response>
        + Sync
        + Send
        + 'static
        + Clone,
    U::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    <U as Service<Request<Body>>>::Future: Send,
{
    let (target_stream, target_certificate) = connect_to_target_with_tls(
        host,
        port,
        additional_host_mapping,
        additional_root_certificates,
    )
    .await?;
    let certificate = spoof_certificate(&target_certificate, &ca)?;
    let identity = native_identity(&certificate, &ca.key)?;
    let client = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity)?);
    let client_stream = client.accept(upgraded).await?;

    let (request_sender, connection) = Builder::new()
        .handshake::<TlsStream<TcpStream>, Body>(target_stream)
        .await?;
    tokio::spawn(connection);
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        RequestSendingSynchronizer::new(request_sender, receiver)
            .run()
            .await
    });
    let third_wheel = ThirdWheel::new(sender);
    let mitm_layer = mitm_maker.layer(third_wheel);

    Http::new()
        .serve_connection(client_stream, mitm_layer)
        .await
        .map_err(|err| err.into())
}

async fn connect_to_target_with_tls(
    host: &str,
    port: &str,
    additional_host_mapping: HashMap<String, String>,
    additional_root_certificates: Vec<Certificate>,
) -> Result<(TlsStream<TcpStream>, X509), Error> {
    let host_address = additional_host_mapping
        .get(host)
        .map_or(host, std::string::String::as_str);
    let target_stream = TcpStream::connect(format!("{}:{}", host_address, port)).await?;

    let mut connector = native_tls::TlsConnector::builder();
    for root_certificate in additional_root_certificates {
        connector.add_root_certificate(root_certificate);
    }
    let connector = connector.build()?;

    let tokio_connector = tokio_native_tls::TlsConnector::from(connector);
    let target_stream = tokio_connector.connect(host, target_stream).await?;
    //TODO: Currently to copy the certificate we do a round trip from one library -> der -> other library. This is inefficient, it should be possible to do it better some how.
    let certificate = &target_stream.get_ref().peer_certificate()?;

    let certificate = match certificate {
        Some(cert) => cert,
        None => {
            return Err(Error::ServerError(
                "Server did not provide a certificate for TLS connection".to_string(),
            ))
        }
    };
    let certificate = openssl::x509::X509::from_der(&certificate.to_der()?)?;

    Ok((target_stream, certificate))
}

fn target_host_port_from_connect(request: &Request<Body>) -> Result<(String, String), Error> {
    let host = request
        .uri()
        .host()
        .map(std::string::ToString::to_string)
        .ok_or_else(|| Error::RequestError("No host found on CONNECT request".to_string()))?;
    let port = request
        .uri()
        .port()
        .map(|x| x.to_string())
        .ok_or_else(|| Error::RequestError("No port found on CONNECT request".to_string()))?;
    Ok((host, port))
}
