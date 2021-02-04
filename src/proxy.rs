use hyper::client::conn::Builder;
use hyper::server::conn::Http;
use openssl::x509::X509;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use log::info;

use http::{Request, Response};

use tokio_native_tls::{TlsAcceptor, TlsStream};

use crate::certificates::spoof_certificate;
use crate::error::Error;
use crate::{RequestCapture, ResponseCapture};

use log::error;

use crate::{
    certificates::{native_identity, CertificateAuthority},
    MitmLayer,
};
use http::header::HeaderName;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, server::Server};

pub(crate) mod mitm;

async fn run_mitm_on_connection<T, S>(
    upgraded: S,
    ca: Arc<CertificateAuthority>,
    host: &str,
    port: &str,
    mitm: T,
) -> Result<(), Error>
where
    T: MitmLayer + std::marker::Sync + std::marker::Send + 'static + Clone,
    S: AsyncRead + AsyncWrite + std::marker::Unpin + 'static,
{
    let (target_stream, target_certificate) = connect_to_target_with_tls(host, port).await?;
    let certificate = spoof_certificate(&target_certificate, &ca)?;
    let identity = native_identity(&certificate, &ca.key)?;
    let client = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity)?);
    let client_stream = client.accept(upgraded).await?;

    let (request_sender, connection) = Builder::new()
        .handshake::<TlsStream<TcpStream>, Body>(target_stream)
        .await?;
    // TODO: will this run forever? Is this essentially a memory leak?
    tokio::spawn(connection.without_shutdown());

    let request_sender = Arc::new(Mutex::new(request_sender));

    Http::new()
        .serve_connection(
            client_stream,
            service_fn(move |mut request: Request<Body>| {
                let shared_sender = request_sender.clone();
                let mitm = mitm.clone();
                async move {
                    match mitm.capture_request(&request).await {
                        RequestCapture::CircumventedResponse(response) => {
                            return Ok::<Response<Body>, Error>(response)
                        }
                        RequestCapture::ModifiedRequest(new_request) => request = new_request,
                        RequestCapture::Continue => {}
                    }

                    *request.uri_mut() = request.uri().path().parse()?;
                    // TODO: don't have this unnecessary overhead every time
                    let proxy_connection: HeaderName =
                        HeaderName::from_lowercase(b"proxy-connection")
                            .expect("Infallible: hardcoded header name");
                    request.headers_mut().remove(&proxy_connection);
                    let mut request_sender = shared_sender.lock().await;
                    let mut response = request_sender.send_request(request).await?;

                    match mitm.capture_response(&response).await {
                        ResponseCapture::ModifiedResponse(new_response) => {
                            response = new_response;
                        }
                        ResponseCapture::Continue => {}
                    }
                    Ok::<Response<Body>, Error>(response)
                }
            }),
        )
        .await
        .map_err(|err| err.into())
}

/// Run a man-in-the-middle TLS proxy
///
/// * `port` - port to accept requests from clients
/// * `mitm` - A `MitmLayer` to capture and/or modify requests and responses
pub async fn start_mitm<T>(port: u16, mitm: T, ca: CertificateAuthority) -> Result<(), Error>
where
    T: MitmLayer + std::marker::Sync + std::marker::Send + 'static + Clone,
{
    let ca = Arc::new(ca);
    let addr = format!("127.0.0.1:{}", port);
    info!("mitm proxy listening on {}", addr);
    let addr = addr
        .parse::<SocketAddr>()
        .expect("Infallible: hardcoded address");
    let make_service = make_service_fn(move |_| {
        // While the state was moved into the make_service closure,
        // we need to clone it here because this closure is called
        // once for every connection.
        //
        // Each connection could send multiple requests, so
        // the `Service` needs a clone to handle later requests.
        let ca = ca.clone();
        let mitm = mitm.clone();

        async move {
            Ok::<_, Error>(service_fn(move |mut req: Request<Body>| {
                let mut res = Response::new(Body::empty());

                // The proxy can only handle CONNECT requests
                if req.method() == http::Method::CONNECT {
                    let target = target_host_port_from_connect(&req);
                    match target {
                        Ok((host, port)) => {
                            // In the case of a TLS tunnel request we spawn a new
                            // service to handle the upgrade. This will only happen
                            // after the currently running function finishes so we need
                            // to spawn it as a separate future.
                            let ca = ca.clone();
                            let mitm = mitm.clone();
                            tokio::task::spawn(async move {
                                match hyper::upgrade::on(&mut req).await {
                                    Ok(upgraded) => {
                                        if let Err(e) =
                                            run_mitm_on_connection(upgraded, ca, &host, &port, mitm).await
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
    });
    Server::bind(&addr)
        .serve(make_service)
        .await
        .map_err(|err| err.into())
}

async fn connect_to_target_with_tls(
    host: &str,
    port: &str,
) -> Result<(TlsStream<TcpStream>, X509), Error> {
    let target_stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    let connector = native_tls::TlsConnector::builder().build()?;
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
        .ok_or(Error::RequestError(
            "No host found on CONNECT request".to_string(),
        ))?;
    let port = request
        .uri()
        .port()
        .map(|x| x.to_string())
        .ok_or(Error::RequestError(
            "No port found on CONNECT request".to_string(),
        ))?;
    Ok((host, port))
}
