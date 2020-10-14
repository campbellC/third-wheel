use futures::sink::SinkExt;
use std::net::SocketAddr;
use std::sync::Arc;

use log::info;

use http::{Request, Response};
use openssl::x509::X509;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;
use tokio_native_tls::{TlsAcceptor, TlsStream};
use tokio_util::codec::Framed;

use crate::certificates::{native_identity, spoof_certificate, CertificateAuthority};
use crate::codecs::http11::{HttpClient, HttpServer};
use crate::error::Error;

pub(crate) mod mitm;
use self::mitm::{MitmLayer, RequestCapture, ResponseCapture};

use http::header::HeaderName;

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
    let mut new_client_listener = TcpListener::bind(&addr).await?;

    loop {
        let (new_client_stream, _) = new_client_listener.accept().await?;
        let mut transport = Framed::new(new_client_stream, HttpClient);
        if let Some(proxy_opening_request) = transport.next().await {
            let proxy_opening_request = proxy_opening_request?;
            if proxy_opening_request.method() == http::Method::CONNECT {
                tokio::spawn(tls_mitm_wrapper(
                    transport,
                    proxy_opening_request,
                    mitm.clone(),
                    ca.clone(),
                ));
            } else {
                unimplemented!();
            }
        }
    }
}

async fn tls_mitm_wrapper(
    client_stream: Framed<TcpStream, HttpClient>,
    opening_request: Request<Vec<u8>>,
    mitm: impl MitmLayer,
    ca: Arc<CertificateAuthority>,
) -> Result<(), Error> {
    tls_mitm(client_stream, opening_request, &ca, mitm).await
}

async fn tls_mitm(
    mut client_stream: Framed<TcpStream, HttpClient>,
    opening_request: Request<Vec<u8>>,
    cert_auth: &Arc<CertificateAuthority>,
    mitm: impl MitmLayer,
) -> Result<(), Error> {
    let (host, port) = target_host_port_from_connect(&opening_request)?;

    if port == "443" {
        let (target_stream, server_certificate) = connect_to_target_with_tls(&host, &port).await?;
        client_stream
            .send(
                &Response::builder()
                    .status(200)
                    .version(http::Version::HTTP_11)
                    .body(Vec::new())
                    .expect("Infallible: hardcoded HTTP response"),
            )
            .await?;

        let certificate = spoof_certificate(&server_certificate, cert_auth)?;
        let identity = native_identity(&certificate, &cert_auth.key)?;
        let client_stream = convert_to_tls(client_stream, identity).await?;
        run_mitm_on_stream(client_stream, target_stream, mitm).await
    } else {
        let target_stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let target_stream = Framed::new(target_stream, HttpServer);
        client_stream
            .send(
                &Response::builder()
                    .status(200)
                    .version(http::Version::HTTP_11)
                    .body(Vec::new())
                    .expect("Infallible: hardcoded HTTP response"),
            )
            .await?;
        run_mitm_on_stream(client_stream, target_stream, mitm).await
    }
}

async fn run_mitm_on_stream<T>(
    mut client_stream: Framed<T, HttpClient>,
    mut target_stream: Framed<T, HttpServer>,
    mitm: impl MitmLayer,
) -> Result<(), Error>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    let proxy_connection: HeaderName =
        HeaderName::from_lowercase(b"proxy-connection").expect("Infallible: hardcoded header name");
    while let Some(request) = client_stream.next().await {
        let mut request = request?;
        match mitm.capture_request(&request).await {
            RequestCapture::CircumventedResponse(response) => {
                client_stream.send(&response).await?;
                continue;
            }
            RequestCapture::ModifiedRequest(new_request) => request = new_request,
            RequestCapture::Continue => {}
        }

        *request.uri_mut() = request.uri().path().parse()?;
        request.headers_mut().remove(&proxy_connection);
        target_stream.send(&request).await?;

        while let Some(response) = target_stream.next().await {
            let mut response = response?;
            match mitm.capture_response(&request, &response).await {
                ResponseCapture::ModifiedResponse(new_response) => {
                    response = new_response;
                }
                ResponseCapture::Continue => {}
            }
            client_stream.send(&response).await?;
        }
    }
    Ok(())
}

async fn convert_to_tls(
    client_stream: Framed<TcpStream, HttpClient>,
    identity: native_tls::Identity,
) -> Result<Framed<TlsStream<TcpStream>, HttpClient>, Error> {
    let client_stream = client_stream.into_inner();
    let client = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity)?);
    let client_stream = client.accept(client_stream).await?;
    Ok(Framed::new(client_stream, HttpClient))
}

fn target_host_port_from_connect(request: &Request<Vec<u8>>) -> Result<(String, String), Error> {
    let host = request
        .uri()
        .host()
        .map(|x| x.to_string())
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

async fn connect_to_target_with_tls(
    host: &str,
    port: &str,
) -> Result<(Framed<TlsStream<TcpStream>, HttpServer>, X509), Error> {
    let target_stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    let connector = native_tls::TlsConnector::builder().build()?;
    let tokio_connector = tokio_native_tls::TlsConnector::from(connector);
    let target_stream = tokio_connector.connect(&host, target_stream).await?;
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

    Ok((Framed::new(target_stream, HttpServer), certificate))
}
