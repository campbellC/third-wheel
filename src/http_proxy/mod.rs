use std::net::SocketAddr;
use std::sync::Arc;
use futures::sink::SinkExt;

use http::{Request, Response};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use tokio_util::codec::Framed;
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::{TlsAcceptor, TlsStream};
use tokio::stream::StreamExt;

use crate::certificates::{load_key_from_file, native_identity, spoof_certificate, CA};
use crate::codecs::http11::{HttpClient, HttpServer};
use crate::SafeResult;

pub mod mitm;
pub use self::mitm::{MitmLayer, RequestCapture, ResponseCapture};

use http::header::HeaderName;

lazy_static! {
    static ref CERT_AUTH: crate::certificates::CA =
        CA::load_from_pem_files("ca/ca_certs/cert.pem", "ca/ca_certs/key.pem").unwrap();
    static ref KEY: PKey<Private> = load_key_from_file("ca/ca_certs/key.pem").unwrap();
}

pub async fn start_mitm<T>(
    port: u16,
    mitm: Arc<T>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: MitmLayer + std::marker::Sync + std::marker::Send,
    T: 'static,
{
    let addr = format!("127.0.0.1:{}", port);
    println!("mitm proxy listening on {}", addr);
    let addr = addr.parse::<SocketAddr>()?;
    let mut new_client_listener = TcpListener::bind(&addr).await?;

    loop {
        let (new_client_stream, _) = new_client_listener.accept().await?;
        let mut transport = Framed::new(new_client_stream, HttpClient);
        if let Some(proxy_opening_request) = transport.next().await {
            match proxy_opening_request {
                Ok(proxy_opening_request) => {
                    if proxy_opening_request.method() == http::Method::CONNECT {
                        tokio::spawn(tls_mitm_wrapper(
                            transport,
                            proxy_opening_request,
                            mitm.clone(),
                        ));
                    }
                }
                Err(e) => {
                    dbg!(e);
                }
            }
        } else {
            unimplemented!();
        }
    }
}

async fn tls_mitm_wrapper<T>(
    client_stream: Framed<TcpStream, HttpClient>,
    opening_request: Request<Vec<u8>>,
    mitm: Arc<T>,
) where
    T: MitmLayer,
{
    tls_mitm(client_stream, opening_request, &CERT_AUTH, &KEY, mitm)
        .await
        .unwrap();
}

async fn tls_mitm<T>(
    mut client_stream: Framed<TcpStream, HttpClient>,
    opening_request: Request<Vec<u8>>,
    cert_auth: &CA,
    private_key: &PKey<Private>,
    mitm: Arc<T>,
) -> SafeResult
where
    T: MitmLayer
{
    let (host, port) = target_host_port(&opening_request);
    let (mut target_stream, server_certificate) = connect_to_target(&host, &port).await;
    client_stream
        .send(
            &Response::builder()
                .status(200)
                .version(http::Version::HTTP_11)
                .body(Vec::new())
                .unwrap(),
        )
        .await?;

    let certificate = spoof_certificate(&server_certificate, cert_auth).unwrap();
    let identity = native_identity(&certificate, private_key);
    let mut client_stream = convert_to_tls(client_stream, identity).await;
    let proxy_connection: HeaderName = HeaderName::from_lowercase(b"proxy-connection").unwrap();

    while let Some(request) = client_stream.next().await {
        let mut request = request.unwrap();
        match mitm.capture_request(&request) {
            RequestCapture::CircumventedResponse(response) => {
                client_stream.send(&response).await.unwrap();
                continue;
            }
            RequestCapture::ModifiedRequest(new_request) => request = new_request,
            RequestCapture::Continue => {}
        }

        *request.uri_mut() = request.uri().path().parse().unwrap();
        request.headers_mut().remove(&proxy_connection);
        target_stream.send(&request).await?;

        let mut response = target_stream.next().await.unwrap()?;
        match mitm.capture_response(&request, &response) {
            ResponseCapture::ModifiedResponse(new_response) => {
                response = new_response;
            }
            ResponseCapture::Continue => {}
        }
        client_stream.send(&response).await.unwrap();
    }

    Ok(())
}

async fn convert_to_tls(
    client_stream: Framed<TcpStream, HttpClient>,
    identity: native_tls::Identity,
) -> Framed<TlsStream<TcpStream>, HttpClient> {
    let client_stream = client_stream.into_inner();
    let client = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity).unwrap());
    let client_stream = client.accept(client_stream).await.unwrap();
    Framed::new(client_stream, HttpClient)
}

fn target_host_port(request: &Request<Vec<u8>>) -> (String, String) {
    let host_header = String::from_utf8(Vec::from(
        request
            .headers()
            .iter()
            .find(|x| x.0 == "Host")
            .unwrap()
            .1
            .as_bytes(),
    ))
    .unwrap();
    let pieces = host_header.split(':').collect::<Vec<&str>>();
    (pieces[0].to_string(), pieces[1].to_string())
}

async fn connect_to_target(
    host: &str,
    port: &str,
) -> (Framed<TlsStream<TcpStream>, HttpServer>, X509) {
    // This format! *cannot* be inlined due to a compiler issue
    // https://github.com/rust-lang/rust/issues/64477
    let target_address = format!("{}:{}", host, port);
    let target_stream = TcpStream::connect(target_address).await.unwrap();
    let connector = native_tls::TlsConnector::builder().build().unwrap();
    let tokio_connector = tokio_native_tls::TlsConnector::from(connector);
    let target_stream = tokio_connector.connect(&host, target_stream).await.unwrap();
    //TODO: investigate a more efficient way of building this - or maybe moving entirely up to native_tls
    let certificate = openssl::x509::X509::from_der(
        &target_stream
            .get_ref()
            .peer_certificate()
            .unwrap()
            .unwrap()
            .to_der()
            .unwrap(),
    )
    .unwrap();
    (Framed::new(target_stream, HttpServer), certificate)
}

pub async fn run_http_proxy(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{}", port);
    println!("http proxy listening on {}", addr);
    let addr = addr.parse::<SocketAddr>()?;

    let mut listener = TcpListener::bind(&addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut transport = Framed::new(stream, HttpClient);
            while let Some(request) = transport.next().await {
                match request {
                    Ok(request) => {
                        let host = String::from_utf8(Vec::from(
                            request
                                .headers()
                                .iter()
                                .find(|x| x.0 == "Host")
                                .unwrap()
                                .1
                                .as_bytes(),
                        ))
                        .unwrap();
                        // This format! cannot be inlined due to a compiler issue
                        // https://github.com/rust-lang/rust/issues/64477
                        let target_address = format!("{}:80", host);
                        let target_stream = TcpStream::connect(target_address).await.unwrap();
                        let mut target_transport = Framed::new(target_stream, HttpServer);
                        target_transport.send(&request).await.unwrap();
                        let response = target_transport
                            .next()
                            .await
                            .unwrap()
                            .expect("valid http response");
                        transport.send(&response).await.unwrap();
                    }
                    Err(e) => {
                        dbg!(e);
                    }
                }
            }
        });
    }
}
