use futures::Future;
use hyper::{Body, Request};
use openssl::{pkey::PKey, rsa::Rsa};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use run_script::{run_script, ScriptOptions};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::iter;
use std::net::SocketAddr;
use third_wheel::*;
use tokio::sync::oneshot;
use tower::Service;

fn random_string() -> String {
    let mut rng = thread_rng();
    let chars: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(7)
        .collect();
    chars.to_lowercase()
}

pub struct TestCertificateLocations {
    base_dir: String,
    server_root_cert: String,
    server_key: String,
    third_wheel_root_cert: String,
    third_wheel_key: String,
}

impl Drop for Harness {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root_certificates.base_dir).unwrap();
        self.server_killer.take().unwrap().send(()).unwrap();
        self.third_wheel_killer.take().unwrap().send(()).unwrap();
    }
}

fn create_server_and_third_wheel_certificates() -> TestCertificateLocations {
    let base_dir = format!("/tmp/third_wheel_testing_{}", random_string());
    std::fs::create_dir(base_dir.clone()).unwrap();

    let server_root_cert = format!("{}/{}", &base_dir, random_string());
    let server_key = format!("{}/{}", &base_dir, random_string());
    let third_wheel_root_cert = format!("{}/{}", &base_dir, random_string());
    let third_wheel_key = format!("{}/{}", &base_dir, random_string());

    let mut options = ScriptOptions::new();
    options.working_directory = Some(base_dir.clone().into());
    run_script!(
        format!(
            r#"
            openssl req -x509 -newkey rsa:4096 -keyout {} -out {} -days 365 -passout pass:"third-wheel" -subj "/C=US/ST=private/L=province/O=city/CN=thirdwheel.com"
            "#, &server_key, &server_root_cert),
        &options
    ).unwrap();
    run_script!(
        format!(
            r#"
            openssl req -x509 -newkey rsa:4096 -keyout {} -out {} -days 365 -passout pass:"third-wheel" -subj "/C=US/ST=private/L=province/O=city/CN=thirdwheel.com"
            "#, &third_wheel_key, &third_wheel_root_cert),
        &options
    ).unwrap();

    TestCertificateLocations {
        base_dir,
        server_root_cert,
        server_key,
        third_wheel_root_cert,
        third_wheel_key,
    }
}

fn run_sign_certificate_for_domain(
    outfile: &str,
    cert_file: &str,
    key_file: &str,
    domain: &str,
) -> Result<(), Error> {
    let ca = CertificateAuthority::load_from_pem_files(cert_file, key_file)?;
    let site_cert = create_signed_certificate_for_domain(domain, &ca)?;

    let mut site_cert_file = File::create(outfile)?;
    site_cert_file.write_all(&site_cert.to_pem()?)?;
    Ok(())
}

fn spawn_server(
    server_key_location: &str,
    server_cert_location: &str,
) -> (SocketAddr, oneshot::Sender<()>, impl Future<Output = ()>) {
    use warp::Filter;

    // Match any request and return hello world!
    let routes = warp::any().map(|| {
        log::info!("Received request");
        "Hello, World!"
    });
    let addr: SocketAddr = "127.0.0.1:0"
        .parse()
        .expect("Infallible: hardcoded socket address");
    let (tx, rx) = oneshot::channel();

    let key = get_file_bytes(server_key_location);
    let key = PKey::from_rsa(
        Rsa::private_key_from_pem_passphrase(&key, &"third-wheel".as_bytes()).unwrap(),
    )
    .unwrap();

    let (server_address, server) = warp::serve(routes)
        .tls()
        .key(key.private_key_to_pem_pkcs8().unwrap())
        .cert_path(server_cert_location)
        .bind_with_graceful_shutdown(addr, async { rx.await.ok().unwrap() });
    return (server_address, tx, server);
}

fn get_file_bytes(filename: &str) -> Vec<u8> {
    let mut cert_file = File::open(filename).unwrap();
    let mut cert: Vec<u8> = vec![];
    io::copy(&mut cert_file, &mut cert).unwrap();
    cert
}

pub struct Harness {
    pub test_site_and_port: String,
    root_certificates: TestCertificateLocations,
    server_killer: Option<oneshot::Sender<()>>,
    third_wheel_killer: Option<oneshot::Sender<()>>,
    pub client: reqwest::Client,
}

pub async fn set_up_for_test() -> Harness {
    // set up certificates for third wheel and the test server
    let root_certificates = create_server_and_third_wheel_certificates();
    let server_cert_location = format!("{}/{}.pem", &root_certificates.base_dir, random_string());
    log::info!("Server certificate stored at: {}", server_cert_location);
    let test_domain_name = format!("{}.com", random_string());
    log::info!("Server domain name: {}", test_domain_name);
    run_sign_certificate_for_domain(
        &server_cert_location,
        &root_certificates.server_root_cert,
        &root_certificates.server_key,
        &test_domain_name,
    )
    .unwrap();

    let (server_addr, server_killer, server) =
        spawn_server(&root_certificates.server_key, &server_cert_location);

    let mut host_mapping = HashMap::new();
    host_mapping.insert(test_domain_name.clone(), "127.0.0.1".to_string());

    let server_root_cert =
        native_tls::Certificate::from_pem(&get_file_bytes(&root_certificates.server_root_cert))
            .unwrap();

    let third_wheel_ca = CertificateAuthority::load_from_pem_files(
        &root_certificates.third_wheel_root_cert,
        &root_certificates.third_wheel_key,
    )
    .unwrap();

    let trivial_mitm = MitmProxy::builder(
        mitm_layer(|req: Request<Body>, mut third_wheel: ThirdWheel| third_wheel.call(req)),
        third_wheel_ca,
    )
    .additional_root_certificates(vec![server_root_cert])
    .additional_host_mappings(host_mapping)
    .build();

    let (third_wheel_killer, receiver) = tokio::sync::oneshot::channel();
    let (third_wheel_address, mitm_fut) = trivial_mitm
        .bind_with_graceful_shutdown("127.0.0.1:0".parse().unwrap(), async {
            receiver.await.ok().unwrap()
        });
    log::info!("Initiating server");
    tokio::spawn(server);
    log::info!("Initiating mitm proxy");
    tokio::spawn(mitm_fut);

    let client = reqwest_client(
        third_wheel_address,
        &root_certificates.third_wheel_root_cert,
    );

    Harness {
        test_site_and_port: format!("{}:{}", test_domain_name, server_addr.port()),
        client,
        root_certificates,
        server_killer: Some(server_killer),
        third_wheel_killer: Some(third_wheel_killer),
    }
}

fn reqwest_client(
    third_wheel_addr: SocketAddr,
    third_wheel_cert_location: &str,
) -> reqwest::Client {
    let third_wheel_cert =
        reqwest::Certificate::from_pem(&get_file_bytes(third_wheel_cert_location)).unwrap();
    reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::https(format!(
                "http://{}:{}",
                third_wheel_addr.ip(),
                third_wheel_addr.port()
            ))
            .unwrap(),
        )
        .add_root_certificate(third_wheel_cert)
        .build()
        .unwrap()
}
