use futures::Future;
use http::{Request, Response};
use hyper::service::Service;
use hyper::Body;
use std::fs::File;
use std::io::prelude::*;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::timeout;

use argh::FromArgs;
use cookie::Cookie;
use har::v1_2::{self, Entries, Headers};
use http;

use third_wheel::*;

/// Run a TLS mitm proxy that records a HTTP ARchive (HAR) file of the session.
/// Currently this is a proof-of-concept and won't handle binary data or non-utf8 encodings
#[derive(FromArgs)]
struct StartMitm {
    /// port to bind proxy to
    #[argh(option, short = 'p', default = "8080")]
    port: u16,

    /// output file to save the HAR to
    #[argh(option, short = 'o', default = "\"third-wheel.har\".to_string()")]
    outfile: String,

    /// number of seconds to run the proxy for
    #[argh(option, short = 's', default = "30")]
    seconds_to_run_for: u64,

    /// pem file for self-signed certificate authority certificate
    #[argh(option, short = 'c', default = "\"ca/ca_certs/cert.pem\".to_string()")]
    cert_file: String,

    /// pem file for private signing key for the certificate authority
    #[argh(option, short = 'k', default = "\"ca/ca_certs/key.pem\".to_string()")]
    key_file: String,
}

#[derive(Clone)]
struct HarSender {
    inner: Arc<Mutex<ThirdWheel>>,
    sender: mpsc::Sender<Entries>,
}

#[derive(Clone)]
struct MakeHarSender {
    sender: mpsc::Sender<Entries>,
}

impl MakeMitm<HarSender> for MakeHarSender {
    fn new_mitm(&self, inner: ThirdWheel) -> HarSender {
        HarSender {
            inner: Arc::new(Mutex::new(inner)),
            sender: self.sender.clone(),
        }
    }
}

impl Service<Request<Body>> for HarSender {
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        return if let Ok(mut third_wheel) = self.inner.try_lock() {
            third_wheel.poll_ready(cx)
        } else {
            std::task::Poll::Pending
        };
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let third_wheel = self.inner.clone();
        let sent_self = self.clone();
        let fut = async move {
            let (req_parts, req_body) = req.into_parts();

            let body_bytes = hyper::body::to_bytes(req_body).await.unwrap().to_vec();
            let mut copied_bytes = Vec::with_capacity(body_bytes.len());
            copied_bytes.extend(&body_bytes);
            let har_request = copy_from_http_request_to_har(&req_parts, copied_bytes).await;

            let body = Body::from(hyper::body::Bytes::from(body_bytes));
            let req = Request::<Body>::from_parts(req_parts, body);

            let mut third_wheel = third_wheel.lock().await;
            let response = third_wheel.call(req).await.unwrap();

            let (res_parts, res_body) = response.into_parts();
            let body_bytes: Vec<u8> = hyper::body::to_bytes(res_body).await.unwrap().to_vec();
            let mut copied_bytes = Vec::with_capacity(body_bytes.len());
            copied_bytes.extend(&body_bytes);
            let har_response = copy_from_http_response_to_har(&res_parts, copied_bytes).await;

            let body = Body::from(hyper::body::Bytes::from(body_bytes));
            let response = Response::<Body>::from_parts(res_parts, body);

            let entries = Entries {
                request: har_request,
                response: har_response,
                time: 0.0,
                server_ip_address: None,
                connection: None,
                comment: None,
                started_date_time: "bla".to_string(),
                cache: v1_2::Cache {
                    before_request: None,
                    after_request: None,
                },
                timings: v1_2::Timings {
                    blocked: None,
                    dns: None,
                    connect: None,
                    send: 0.0,
                    wait: 0.0,
                    receive: 0.0,
                    ssl: None,
                    comment: None,
                },
                pageref: None,
            };
            sent_self.sender.send(entries).await.unwrap();
            Ok(response)
        };
        return Box::pin(fut);
    }
}

async fn copy_from_http_request_to_har(
    parts: &http::request::Parts,
    body: Vec<u8>,
) -> v1_2::Request {
    let method = parts.method.as_str().to_string();
    let url = format!("{}", parts.uri);
    let http_version = "HTTP/1.1".to_string(); // Hardcoded for now because third-wheel only handles HTTP/1.1
    let mut headers = Vec::new();
    for (name, value) in &parts.headers {
        headers.push(Headers {
            name: name.as_str().to_string(),
            value: value.to_str().unwrap().to_string(),
            comment: None,
        })
    }
    let headers_size: i64 = headers.iter().fold(0, |sum, headers| {
        sum + (headers.name.len() as i64 + headers.value.len() as i64)
    });

    let cookies: Vec<v1_2::Cookies> = parts
        .headers
        .iter()
        .filter(|(key, _)| key == &http::header::COOKIE)
        .map(|(_, value)| parse_cookie(value.to_str().unwrap()))
        .collect();

    let body = String::from_utf8(body).unwrap(); // TODO: handle other encodings correctly
    let body_size = body.len() as i64;
    let mime_type = parts
        .headers
        .iter()
        .filter(|(key, _)| key == &http::header::CONTENT_TYPE)
        .map(|(_, value)| value.to_str().unwrap().to_string())
        .nth(0)
        .unwrap_or("".to_string());
    let post_data = if body_size > 0 {
        Some(v1_2::PostData {
            mime_type,
            text: body,
            params: None,
            comment: None,
        })
    } else {
        None
    };

    v1_2::Request {
        method,
        url,
        http_version,
        cookies,
        headers,
        query_string: Vec::new(),
        post_data,
        headers_size,
        body_size,
        comment: None,
    }
}

async fn copy_from_http_response_to_har(
    parts: &http::response::Parts,
    body: Vec<u8>,
) -> v1_2::Response {
    let mut headers = Vec::new();
    for (name, value) in &parts.headers {
        headers.push(Headers {
            name: name.as_str().to_string(),
            value: value.to_str().unwrap().to_string(),
            comment: None,
        })
    }
    let headers_size: i64 = headers.iter().fold(0, |sum, headers| {
        sum + (headers.name.len() as i64 + headers.value.len() as i64)
    });

    let cookies: Vec<String> = parts
        .headers
        .iter()
        .filter(|(key, _)| key == &http::header::SET_COOKIE)
        .map(|(_, value)| value.to_str().unwrap().to_string())
        .collect();
    let cookies: Vec<har::v1_2::Cookies> = cookies
        .iter()
        .map(|cookie_string| parse_cookie(cookie_string))
        .collect();

    let mime_type = parts
        .headers
        .iter()
        .filter(|(key, _)| key == &http::header::CONTENT_TYPE)
        .map(|(_, value)| value.to_str().unwrap().to_string())
        .nth(0)
        .unwrap_or("".to_string());

    let redirect_url = if parts.status.is_redirection() {
        parts
            .headers
            .iter()
            .filter(|(key, _)| key == &http::header::LOCATION)
            .map(|(_, value)| value.to_str().unwrap_or("").to_string())
            .nth(0)
            .unwrap()
    } else {
        "".to_string()
    };

    let http_version = "HTTP/1.1".to_string(); // Hardcoded for now because third-wheel only handles HTTP/1.1

    let body = String::from_utf8(body).unwrap(); // TODO: handle other encodings correctly
    let body_size = body.len() as i64;
    let content = v1_2::Content {
        size: body_size,
        compression: None,
        mime_type,
        text: Some(body),
        encoding: None, //TODO: handle the base64 case
        comment: None,
    };
    v1_2::Response {
        charles_status: None, //TODO: once https://github.com/mandrean/har-rs/issues/13 is resolved remove this
        http_version,
        status: parts.status.as_u16() as i64,
        status_text: parts.status.canonical_reason().unwrap_or("").to_string(),
        cookies,
        headers,
        headers_size,
        body_size,
        comment: None,
        redirect_url,
        content,
    }
}

fn parse_cookie(cookie_str: &str) -> v1_2::Cookies {
    let parsed = Cookie::parse(cookie_str).unwrap();
    v1_2::Cookies {
        name: parsed.name().to_string(),
        value: parsed.value().to_string(),
        path: parsed.path().map(|p| p.to_string()),
        domain: parsed.domain().map(|d| d.to_string()),
        expires: parsed.expires().map(|e| e.format("%F %r %z")), // TODO: ISO 8601 format
        http_only: parsed.http_only(),
        secure: parsed.secure(),
        comment: None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    simple_logger::SimpleLogger::new().init().unwrap();
    let args: StartMitm = argh::from_env();
    let ca = CertificateAuthority::load_from_pem_files(&args.cert_file, &args.key_file)?;
    let (sender, mut receiver) = mpsc::channel(100);
    let make_har_sender = MakeHarSender { sender };
    let result = timeout(
        Duration::from_secs(args.seconds_to_run_for),
        start_mitm(args.port, make_har_sender, ca),
    )
    .await;

    let mut entries = Vec::new();
    while let Some(entry) = receiver.recv().await {
        entries.push(entry);
    }

    let out = har::Har {
        log: har::Spec::V1_2(v1_2::Log {
            entries,
            browser: None,
            comment: None,
            pages: None,
            creator: v1_2::Creator {
                name: "third-wheel".to_string(),
                version: "0.5".to_string(),
                comment: None,
            },
        }),
    };

    let mut file = File::create(args.outfile)?;
    file.write_all(har::to_json(&out).unwrap().as_bytes())?;
    result.unwrap_or(Ok(()))
}
