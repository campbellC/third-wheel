mod certificates;

use crate::certificates::create_signed_certificate_for_domain;
use crate::certificates::CA;

mod http_proxy;

use http_proxy::{start_mitm,run_http_proxy};

mod codecs;

use codecs::http11::{HttpServer, HttpClient};

use std::fs::File;
use std::io::Write;

use clap::{Arg, ArgMatches, App, SubCommand};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::codec::Framed;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use native_tls::TlsConnector;
use tokio_tls::TlsAcceptor;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
#[macro_use]
extern crate lazy_static;

type SafeResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> SafeResult {
    let matches = App::new("third-wheel")
        .version("0.1")
        .author("Chris Campbell")
        .about("A Rust clone of mitmproxy for fast and lightweight TLS proxying")
        .subcommand(SubCommand::with_name("mitm")
            .about("Run a mitm proxy")
            .arg(Arg::with_name("port")
                .short("p")
                .help("Port to connect to")
                .required(false)
                .default_value("8080")
                .validator(|p| if let Err(_e) = p.parse::<u16>() {
                    Err(String::from("Expected an integer"))
                } else { Ok(()) }
                )
            )
        )
        .subcommand(SubCommand::with_name("http-proxy")
            .about("Run a simple http proxy")
            .arg(Arg::with_name("port")
                .short("p")
                .help("Port to connect to")
                .required(false)
                .default_value("8080")
                .validator(|p| if let Err(_e) = p.parse::<u16>() {
                    Err(String::from("Expected an integer"))
                } else { Ok(()) }
                )
            )
        )
        .subcommand(SubCommand::with_name("sign-cert-for-domain")
            .about("Sign a x509 certificate for a given domain")
            .arg(Arg::from_usage("<DOMAIN> 'The domain to sign the certificate for'"))
            .arg(Arg::from_usage("-o --outfile=[outfile] 'The file to store the certificate in'")
                .default_value("site.pem"))

            .arg(Arg::from_usage("-c --ca-cert-file=[cert_file] 'The pem file containing the ca certificate'")
                .default_value("./ca/ca_certs/cert.pem"))
            .arg(Arg::from_usage("-k --ca-key-file=[key_file] 'The pem file containing the ca key'")
                .default_value("./ca/ca_certs/key.pem"))
        ).subcommand(SubCommand::with_name("testing"))
        .get_matches();
    run(matches).await
}

async fn run(matches: ArgMatches<'_>) -> SafeResult {
    match matches.subcommand() {
        ("testing", Some(_m)) => testing_main().await,
        ("mitm", Some(m)) => start_mitm(
            m.value_of("port").unwrap().parse().unwrap()
        ).await,
        ("http-proxy", Some(m)) => run_http_proxy(
            m.value_of("port").unwrap().parse().unwrap()
        ).await,
        ("sign-cert-for-domain", Some(m)) => {
            run_sign_certificate_for_domain(
                m.value_of("outfile").unwrap(),
                m.value_of("ca-cert-file").unwrap(),
                m.value_of("ca-key-file").unwrap(),
                m.value_of("DOMAIN").unwrap(),
            ).await
        }
        _ => Ok(())
    }
}

async fn testing_main() -> SafeResult {
    let port = 8080;
    let addr = format!("127.0.0.1:{}", port);
    println!("http proxy listening on {}", addr);
    let addr = addr.parse::<SocketAddr>()?;

    let mut listener = TcpListener::bind(&addr).await?;

    let (stream, _) = listener.accept().await?;
    let mut transport = Framed::new(stream, HttpClient);
    if let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                let host = String::from_utf8(Vec::from(request.headers().iter()
                    .filter(|x| x.0 == "Host")
                    .next()
                    .unwrap()
                    .1.as_bytes())).unwrap();
                assert!(request.method() == http::Method::CONNECT);
                let (host, port) = {
                    let pieces = host.split(":").collect::<Vec<&str>>();
                    (pieces[0], pieces[1])
                };
                dbg!(&host);

                let target_address = format!("{}:{}", host, port);
                let target_stream = TcpStream::connect(target_address).await.unwrap();
                let connector = TlsConnector::builder().build().unwrap();
                let tokio_connector = tokio_tls::TlsConnector::from(connector);
                let target_stream = tokio_connector.connect(&host, target_stream).await.unwrap();
                let _certificate = openssl::x509::X509::from_der(&target_stream.peer_certificate().unwrap().unwrap().to_der().unwrap()).unwrap();
                let mut target_transport = Framed::new(target_stream, HttpServer);
                transport.send(http::Response::builder().status(200).version(http::Version::HTTP_11).body(Vec::new()).unwrap()).await.unwrap();
                //TODO: don't just sign a new cert but actually solve the problem
                let ca = CA::load_from_pem_files("ca/ca_certs/cert.pem", "ca/ca_certs/key.pem").unwrap();
                let certificate = create_signed_certificate_for_domain(&host, &ca).unwrap();
                let client_stream = transport.into_inner();


                let key = {
                    let mut key_file = File::open("ca/ca_certs/key.pem").unwrap();
                    let mut key: Vec<u8> = vec![];
                    std::io::copy(&mut key_file, &mut key).unwrap();
                    PKey::from_rsa(Rsa::private_key_from_pem(&key).unwrap()).unwrap()
                };
                let pkcs = Pkcs12::builder().build(&"", &"", &key, &certificate).unwrap().to_der().unwrap();
                let identity = native_tls::Identity::from_pkcs12(&pkcs, &"").unwrap();
                let client = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity).unwrap());
                let client_stream = client.accept(client_stream).await.unwrap();
                let mut transport = Framed::new(client_stream, HttpClient);


                if let Some(request) = transport.next().await {
                    dbg!(&request);
                    target_transport.send(request.unwrap()).await.unwrap();
                    let response = target_transport.next().await.unwrap().expect("valid http response");
                    dbg!(&response);
                    transport.send(response).await.unwrap();
                } else {
                    println!("error");
                }
            }
            Err(e) => { dbg!(e); }
        }
    } else {
        println!("error");
    }
    Ok(())
}

async fn run_sign_certificate_for_domain(outfile: &str, cert_file: &str, key_file: &str, domain: &str) -> SafeResult {
    let ca = CA::load_from_pem_files(cert_file, key_file)?;
    let site_cert = create_signed_certificate_for_domain(domain, &ca)?;

    let mut site_cert_file = File::create(outfile)?;
    site_cert_file.write_all(&site_cert.to_pem()?)?;
    Ok(())
}
