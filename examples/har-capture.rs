use std::fs::File;
use std::io::prelude::*;
use std::time::Duration;
use tokio::time::timeout;

use async_trait::async_trait;
use std::sync::Mutex;

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

struct HarCapturer {
    entries: Mutex<Vec<Entries>>,
}

#[async_trait]
impl MitmLayer for HarCapturer {
    async fn capture_request(&self, _: &http::Request<Vec<u8>>) -> RequestCapture {
        RequestCapture::Continue
    }

    async fn capture_response(
        &self,
        request: &http::Request<Vec<u8>>,
        response: &http::Response<Vec<u8>>,
    ) -> ResponseCapture {
        let har_request = copy_from_http_request_to_har(request);
        let har_response = copy_from_http_response_to_har(response);
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
        self.entries.lock().unwrap().push(entries);

        ResponseCapture::Continue
    }
}

fn copy_from_http_request_to_har(request: &http::Request<Vec<u8>>) -> v1_2::Request {
    let method = request.method().as_str().to_string();
    let url = format!("{}", request.uri());
    let http_version = "HTTP/1.1".to_string(); // Hardcoded for now because third-wheel only handles HTTP/1.1
    let mut headers = Vec::new();
    for (name, value) in request.headers() {
        headers.push(Headers {
            name: name.as_str().to_string(),
            value: value.to_str().unwrap().to_string(),
            comment: None,
        })
    }
    let headers_size: i64 = headers.iter().fold(0, |sum, headers| {
        sum + (headers.name.len() as i64 + headers.value.len() as i64)
    });

    let cookies: Vec<v1_2::Cookies> = request
        .headers()
        .iter()
        .filter(|(key, _)| key == &http::header::COOKIE)
        .map(|(_, value)| parse_cookie(value.to_str().unwrap()))
        .collect();

    let body = String::from_utf8(request.body().to_vec()).unwrap(); // TODO: handle other encodings correctly
    let body_size = body.len() as i64;
    let mime_type = request
        .headers()
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

fn copy_from_http_response_to_har(response: &http::Response<Vec<u8>>) -> v1_2::Response {
    let mut headers = Vec::new();
    for (name, value) in response.headers() {
        headers.push(Headers {
            name: name.as_str().to_string(),
            value: value.to_str().unwrap().to_string(),
            comment: None,
        })
    }
    let headers_size: i64 = headers.iter().fold(0, |sum, headers| {
        sum + (headers.name.len() as i64 + headers.value.len() as i64)
    });

    let cookies: Vec<String> = response
        .headers()
        .iter()
        .filter(|(key, _)| key == &http::header::SET_COOKIE)
        .map(|(_, value)| value.to_str().unwrap().to_string())
        .collect();
    let cookies: Vec<har::v1_2::Cookies> = cookies
        .iter()
        .map(|cookie_string| parse_cookie(cookie_string))
        .collect();

    let mime_type = response
        .headers()
        .iter()
        .filter(|(key, _)| key == &http::header::CONTENT_TYPE)
        .map(|(_, value)| value.to_str().unwrap().to_string())
        .nth(0)
        .unwrap_or("".to_string());

    let redirect_url = if response.status().is_redirection() {
        response
            .headers()
            .iter()
            .filter(|(key, _)| key == &http::header::LOCATION)
            .map(|(_, value)| value.to_str().unwrap_or("").to_string())
            .nth(0)
            .unwrap()
    } else {
        "".to_string()
    };

    let http_version = "HTTP/1.1".to_string(); // Hardcoded for now because third-wheel only handles HTTP/1.1

    let body = String::from_utf8(response.body().to_vec()).unwrap(); // TODO: handle other encodings correctly
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
        status: response.status().as_u16() as i64,
        status_text: response
            .status()
            .canonical_reason()
            .unwrap_or("")
            .to_string(),
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
    simple_logger::init().unwrap();
    let args: StartMitm = argh::from_env();
    let ca = CertificateAuthority::load_from_pem_files(&args.cert_file, &args.key_file)?;
    let capturer = HarCapturer {
        entries: Mutex::new(Vec::new()),
    };
    let capturer = wrap_mitm_in_arc!(capturer);
    let result = timeout(
        Duration::from_secs(args.seconds_to_run_for),
        start_mitm(args.port, capturer.clone(), ca),
    )
    .await;

    let entries = capturer
        .entries
        .lock()
        .unwrap()
        .iter()
        .map(|x| x.clone())
        .collect();
    let out = har::Har {
        log: har::Spec::V1_2(v1_2::Log {
            entries,
            browser: None,
            comment: None,
            pages: None,
            creator: v1_2::Creator {
                name: "third-wheel".to_string(),
                version: "0.3".to_string(),
                comment: None,
            },
        }),
    };

    let mut file = File::create(args.outfile)?;
    file.write_all(har::to_json(&out).unwrap().as_bytes())?;
    result.unwrap_or(Ok(()))
}
