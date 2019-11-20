mod certificates;

use crate::certificates::create_signed_certificate_for_domain;
use crate::certificates::CA;

mod http_proxy;

use http_proxy::{run_http_proxy, start_mitm};

mod codecs;

use codecs::http11::{HttpClient, HttpServer};

use std::fs::File;
use std::io::Write;

use clap::{App, Arg, ArgMatches, SubCommand};
use futures_util::{SinkExt, StreamExt};
use native_tls::TlsConnector;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use std::net::SocketAddr;
use tokio::codec::Framed;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_tls::TlsAcceptor;
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
        ("mitm", Some(m)) => start_mitm(m.value_of("port").unwrap().parse().unwrap()).await,
        ("http-proxy", Some(m)) => {
            run_http_proxy(m.value_of("port").unwrap().parse().unwrap()).await
        }
        ("sign-cert-for-domain", Some(m)) => {
            run_sign_certificate_for_domain(
                m.value_of("outfile").unwrap(),
                m.value_of("ca-cert-file").unwrap(),
                m.value_of("ca-key-file").unwrap(),
                m.value_of("DOMAIN").unwrap(),
            )
            .await
        }
        _ => Ok(()),
    }
}

async fn testing_main() -> SafeResult {
    Ok(())
}

async fn run_sign_certificate_for_domain(
    outfile: &str,
    cert_file: &str,
    key_file: &str,
    domain: &str,
) -> SafeResult {
    let ca = CA::load_from_pem_files(cert_file, key_file)?;
    let site_cert = create_signed_certificate_for_domain(domain, &ca)?;

    let mut site_cert_file = File::create(outfile)?;
    site_cert_file.write_all(&site_cert.to_pem()?)?;
    Ok(())
}
