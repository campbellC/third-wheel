/* Copyright (c) 2019 Tokio Contributors
Modified copyright 2019 third-wheel contributors

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR Other LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OtherWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR Other
DEALINGS IN THE SOFTWARE. */

// Code borrowed from https://github.com/tokio-rs/tokio/blob/master/examples/tinyhttp.rs
use std::str::FromStr;
use std::{fmt, io};

use bytes::BytesMut;
use http::{header::HeaderValue, Request, Response};
use tokio::codec::{Decoder, Encoder};

use super::body::BodyParser;

pub struct HttpServer;

impl Encoder for HttpServer {
    type Item = Request<Vec<u8>>;
    type Error = io::Error;

    fn encode(&mut self, item: Request<Vec<u8>>, dst: &mut BytesMut) -> io::Result<()> {
        use std::fmt::Write;
        write!(
            BytesWrite(dst),
            "{} {} {:?}\r\n",
            item.method(),
            item.uri(),
            item.version(),
        )
        .unwrap();

        for (k, v) in item.headers() {
            dst.extend_from_slice(k.as_str().as_bytes());
            dst.extend_from_slice(b": ");
            dst.extend_from_slice(v.as_bytes());
            dst.extend_from_slice(b"\r\n");
        }

        dst.extend_from_slice(b"\r\n");
        dst.extend_from_slice(item.body());

        return Ok(());

        // Right now `write!` on `Vec<u8>` goes through io::Write and is not
        // super speedy, so inline a less-crufty implementation here which
        // doesn't go through io::Error.
        struct BytesWrite<'a>(&'a mut BytesMut);

        impl fmt::Write for BytesWrite<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.0.extend_from_slice(s.as_bytes());
                Ok(())
            }

            fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
                fmt::write(self, args)
            }
        }
    }
}

impl Decoder for HttpServer {
    type Item = Response<Vec<u8>>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Response<Vec<u8>>>> {
        // TODO: we should grow this headers array if parsing fails and asks
        //       for more headers
        let mut headers = [None; 16];
        let (status, _reason, version, amt) = {
            let mut parsed_headers = [httparse::EMPTY_HEADER; 16];
            let mut r = httparse::Response::new(&mut parsed_headers);
            let status = r.parse(src).map_err(|e| {
                let msg = format!("failed to parse http response: {:?}", e);
                io::Error::new(io::ErrorKind::Other, msg)
            })?;

            let amt = match status {
                httparse::Status::Complete(amt) => amt,
                httparse::Status::Partial => {
                    return Ok(None);
                }
            };

            let toslice = |a: &[u8]| {
                let start = a.as_ptr() as usize - src.as_ptr() as usize;
                assert!(start < src.len());
                (start, start + a.len())
            };

            let mut body_parser: BodyParser = BodyParser::Empty;
            for (i, header) in r.headers.iter().enumerate() {
                if header.name.to_lowercase() == "transfer-encoding" {
                    assert!(header.value == b"chunked");
                    body_parser = BodyParser::Chunked;
                } else if header.name.to_lowercase() == "content-length" {
                    body_parser = BodyParser::ContentLength(
                        String::from_utf8(header.value.to_vec())
                            .unwrap()
                            .parse()
                            .unwrap(),
                    )
                }
                let k = toslice(header.name.as_bytes());
                let v = toslice(header.value);
                headers[i] = Some((k, v));
            }

            if !body_parser.is_complete(&src[amt..]) {
                return Ok(None);
            }

            (
                r.code.unwrap(),
                toslice(r.reason.unwrap().as_bytes()),
                r.version.unwrap(),
                amt,
            )
        };

        if version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "only HTTP/1.1 accepted but received {}",
                    String::from_utf8(src.to_vec()).unwrap()
                ),
            ));
        }
        let pre_body = src.split_to(amt).freeze();
        let mut ret = Response::builder();
        ret.status(status);
        ret.version(http::Version::HTTP_11);
        for header in headers.iter() {
            let (k, v) = match *header {
                Some((ref k, ref v)) => (k, v),
                None => break,
            };
            let value = unsafe { HeaderValue::from_shared_unchecked(pre_body.slice(v.0, v.1)) };
            ret.header(&pre_body[k.0..k.1], value);
        }

        let response = ret
            .body(src.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Some(response))
    }
}

pub struct HttpClient;

//TODO: modify this for different versions of HTTP1?
impl Encoder for HttpClient {
    type Item = Response<Vec<u8>>;
    type Error = io::Error;

    fn encode(&mut self, item: Response<Vec<u8>>, dst: &mut BytesMut) -> io::Result<()> {
        use std::fmt::Write;

        write!(
            BytesWrite(dst),
            "{:?} {}\r\n",
            item.version(),
            item.status(),
        )
        .unwrap();

        for (k, v) in item.headers() {
            dst.extend_from_slice(k.as_str().as_bytes());
            dst.extend_from_slice(b": ");
            dst.extend_from_slice(v.as_bytes());
            dst.extend_from_slice(b"\r\n");
        }

        dst.extend_from_slice(b"\r\n");
        dst.extend_from_slice(item.body());

        return Ok(());

        // Right now `write!` on `Vec<u8>` goes through io::Write and is not
        // super speedy, so inline a less-crufty implementation here which
        // doesn't go through io::Error.
        struct BytesWrite<'a>(&'a mut BytesMut);

        impl fmt::Write for BytesWrite<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.0.extend_from_slice(s.as_bytes());
                Ok(())
            }

            fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
                fmt::write(self, args)
            }
        }
    }
}

impl Decoder for HttpClient {
    type Item = Request<Vec<u8>>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Request<Vec<u8>>>> {
        // TODO: we should grow this headers array if parsing fails and asks
        //       for more headers
        let mut headers = [None; 16];
        let (method, path, version, amt) = {
            let mut parsed_headers = [httparse::EMPTY_HEADER; 16];
            let mut r = httparse::Request::new(&mut parsed_headers);
            let status = r.parse(src).map_err(|e| {
                let msg = format!("failed to parse http request: {:?}", e);
                io::Error::new(io::ErrorKind::Other, msg)
            })?;

            let amt = match status {
                httparse::Status::Complete(amt) => amt,
                httparse::Status::Partial => return Ok(None),
            };

            let toslice = |a: &[u8]| {
                let start = a.as_ptr() as usize - src.as_ptr() as usize;
                assert!(start < src.len());
                (start, start + a.len())
            };

            // Now we need to check if the body has been fully delivered as
            // httparse doesn't handle that for you
            let mut body_parser: BodyParser = BodyParser::Empty;
            for (i, header) in r.headers.iter().enumerate() {
                if header.name.to_lowercase() == "transfer-encoding" {
                    assert!(header.value == b"chunked");
                    body_parser = BodyParser::Chunked;
                } else if header.name.to_lowercase() == "content-length" {
                    body_parser = BodyParser::ContentLength(
                        String::from_utf8(header.value.to_vec())
                            .unwrap()
                            .parse()
                            .unwrap(),
                    )
                }
                let k = toslice(header.name.as_bytes());
                let v = toslice(header.value);
                headers[i] = Some((k, v));
            }

            if !body_parser.is_complete(&src[amt..]) {
                return Ok(None);
            }
            (
                toslice(r.method.unwrap().as_bytes()),
                toslice(r.path.unwrap().as_bytes()),
                r.version.unwrap(),
                amt,
            )
        };
        if version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "only HTTP/1.1 accepted",
            ));
        }
        let pre_body = src.split_to(amt).freeze();
        let mut ret = Request::builder();
        ret.method(&pre_body[method.0..method.1]);
        let uri = http::Uri::from_str(
            &String::from_utf8(pre_body.slice(path.0, path.1).to_vec()).unwrap(),
        );
        ret.uri(uri.unwrap());
        ret.version(http::Version::HTTP_11);
        for header in headers.iter() {
            let (k, v) = match *header {
                Some((ref k, ref v)) => (k, v),
                None => break,
            };
            //TODO: do we really need unsafe code here?!
            let value = unsafe { HeaderValue::from_shared_unchecked(pre_body.slice(v.0, v.1)) };
            ret.header(&pre_body[k.0..k.1], value);
        }

        let req = ret
            .body(src.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Some(req))
    }
}

#[cfg(test)]
mod response_encoding_test {
    use super::*;
    use bytes::BufMut;

    #[test]
    fn decode_200_chunked() {
        let mut server: HttpServer = HttpServer {};
        let mut buf: BytesMut = BytesMut::with_capacity(1000);
        let response = "HTTP/1.1 200 OK\r\nTransfer-encoding: chunked\r\n\r\n1\r\na\r\na\r\nabcdefghij\r\n0\r\n\r\n";
        buf.put(response);
        let expected = Response::builder()
            .version(http::Version::HTTP_11)
            .status(http::StatusCode::OK)
            .header("transfer-encoding", "chunked")
            .body(b"1\r\na\r\na\r\nabcdefghij\r\n0\r\n\r\n".to_vec())
            .unwrap();

        let response = server.decode(&mut buf).unwrap().unwrap();

        assert_response_equal(expected, response);
    }

    #[test]
    fn encode_200_chunked() {
        let mut client: HttpClient = HttpClient {};
        let expected = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n1\r\na\r\na\r\nabcdefghij\r\n0\r\n\r\n";
        let response = Response::builder()
            .version(http::Version::HTTP_11)
            .status(http::StatusCode::OK)
            .header("transfer-encoding", "chunked")
            .body(b"1\r\na\r\na\r\nabcdefghij\r\n0\r\n\r\n".to_vec())
            .unwrap();
        let mut dst: BytesMut = BytesMut::with_capacity(1000);

        client.encode(response, &mut dst).unwrap();

        assert_eq!(expected.to_vec(), dst.to_vec());
    }

    #[test]
    fn encode_302_google_response() {
        let mut client: HttpClient = HttpClient {};
        let expected = b"HTTP/1.1 301 Moved Permanently\r\nlocation: https://www.google.com/\r\ncontent-type: text/html; charset=UTF-8\r\ndate: Sun, 17 Nov 2019 13:37:35 GMT\r\nexpires: Tue, 17 Dec 2019 13:37:35 GMT\r\ncache-control: public, max-age=2592000\r\nserver: gws\r\ncontent-length: 220\r\nx-xss-protection: 0\r\nx-frame-options: SAMEORIGIN\r\nalt-svc: quic=\":443\"; ma=2592000; v=\"46,43\",h3-Q050=\":443\"; ma=2592000,h3-Q049=\":443\"; ma=2592000,h3-Q048=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000\r\n\r\n<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF=\"https://www.google.com/\">here</A>.\r\n</BODY></HTML>\r\n";
        let response = Response::builder()
            .version(http::Version::HTTP_11)
            .status(http::StatusCode::MOVED_PERMANENTLY)
            .header("Location", "https://www.google.com/")
            .header("Content-Type", "text/html; charset=UTF-8")
            .header("Date", "Sun, 17 Nov 2019 13:37:35 GMT")
            .header("Expires", "Tue, 17 Dec 2019 13:37:35 GMT")
            .header("Cache-Control", "public, max-age=2592000")
            .header("Server", "gws")
            .header("Content-Length", "220")
            .header("X-XSS-Protection", "0")
            .header("X-Frame-Options", "SAMEORIGIN")
            .header("Alt-Svc", "quic=\":443\"; ma=2592000; v=\"46,43\",h3-Q050=\":443\"; ma=2592000,h3-Q049=\":443\"; ma=2592000,h3-Q048=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000")
            .body(b"<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF=\"https://www.google.com/\">here</A>.\r\n</BODY></HTML>\r\n".to_vec()).unwrap();
        let mut dst: BytesMut = BytesMut::with_capacity(1000);

        client.encode(response, &mut dst).unwrap();

        assert_eq!(expected.to_vec(), dst.to_vec());
    }

    #[test]
    fn decode_302_google_response() {
        let mut server: HttpServer = HttpServer {};
        let mut buf: BytesMut = BytesMut::with_capacity(1000);
        let response = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.google.com/\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Sun, 17 Nov 2019 13:37:35 GMT\r\nExpires: Tue, 17 Dec 2019 13:37:35 GMT\r\nCache-Control: public, max-age=2592000\r\nServer: gws\r\nContent-Length: 220\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nAlt-Svc: quic=\":443\"; ma=2592000; v=\"46,43\",h3-Q050=\":443\"; ma=2592000,h3-Q049=\":443\"; ma=2592000,h3-Q048=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000\r\n\r\n<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF=\"https://www.google.com/\">here</A>.\r\n</BODY></HTML>\r\n";
        buf.put(response);
        let expected = Response::builder()
            .version(http::Version::HTTP_11)
            .status(http::StatusCode::MOVED_PERMANENTLY)
            .header("Location", "https://www.google.com/")
            .header("Content-Type", "text/html; charset=UTF-8")
            .header("Date", "Sun, 17 Nov 2019 13:37:35 GMT")
            .header("Expires", "Tue, 17 Dec 2019 13:37:35 GMT")
            .header("Cache-Control", "public, max-age=2592000")
            .header("Server", "gws")
            .header("Content-Length", "220")
            .header("X-XSS-Protection", "0")
            .header("X-Frame-Options", "SAMEORIGIN")
            .header("Alt-Svc", "quic=\":443\"; ma=2592000; v=\"46,43\",h3-Q050=\":443\"; ma=2592000,h3-Q049=\":443\"; ma=2592000,h3-Q048=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000")
            .body(b"<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF=\"https://www.google.com/\">here</A>.\r\n</BODY></HTML>\r\n".to_vec()).unwrap();

        let response = server.decode(&mut buf).unwrap().unwrap();

        assert_response_equal(expected, response);
    }

    #[test]
    fn decode_unfinished_chunked() {
        let mut server: HttpServer = HttpServer {};
        let mut buf: BytesMut = BytesMut::with_capacity(1000);
        let request = "HTTP/1.1 200 OK\r\nTransfer-encoding: chunked\r\n\r\n1\r\na";
        buf.put(request);

        let request = server.decode(&mut buf);

        assert!(request.is_ok());
        assert!(request.unwrap().is_none());
    }

    #[test]
    fn decode_unfinished_headers() {
        let mut server: HttpServer = HttpServer {};
        let mut buf: BytesMut = BytesMut::with_capacity(1000);
        let request = "HTTP/1.1 200 OK\r\nTransfer";
        buf.put(request);

        let request = server.decode(&mut buf);

        assert!(request.is_ok());
        assert!(request.unwrap().is_none());
    }

    fn assert_response_equal(expected: Response<Vec<u8>>, actual: Response<Vec<u8>>) {
        assert_eq!(expected.version(), actual.version());
        assert_eq!(expected.body(), actual.body());
        assert_eq!(expected.status(), actual.status());
        for (k, v) in actual.headers().iter() {
            assert_eq!(
                expected
                    .headers()
                    .get(k)
                    .expect("Header missing from expected"),
                v
            );
        }
        for (k, v) in expected.headers().iter() {
            assert_eq!(
                actual.headers().get(k).expect("Header missing from actual"),
                v
            );
        }
    }
}

#[cfg(test)]
mod request_encoding_test {
    use super::*;
    use bytes::BufMut;

    #[test]
    fn encode_get() {
        let mut server: HttpServer = HttpServer {};
        let request = Request::builder()
            .method(http::Method::GET)
            .version(http::Version::HTTP_11)
            .uri("/")
            .header("Host", "google.com")
            .body(b"".to_vec())
            .unwrap();
        let expected_bytes = b"GET / HTTP/1.1\r\nhost: google.com\r\n\r\n";
        let mut dst = BytesMut::with_capacity(1000);

        server.encode(request, &mut dst).unwrap();

        assert_eq!(expected_bytes.to_vec(), dst.to_vec());
    }

    #[test]
    fn decode_get() {
        let mut client: HttpClient = HttpClient {};
        let mut buf: BytesMut = BytesMut::with_capacity(1000);
        let request = "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n";
        buf.put(request);
        let expected = Request::builder()
            .method(http::Method::GET)
            .version(http::Version::HTTP_11)
            .uri("/")
            .header("Host", "google.com")
            .body(b"".to_vec())
            .unwrap();

        let request = client.decode(&mut buf).unwrap().unwrap();

        assert_request_equal(expected, request);
    }

    #[test]
    fn encode_post_chunked() {
        let mut server: HttpServer = HttpServer {};
        let request = Request::builder()
            .method(http::Method::POST)
            .version(http::Version::HTTP_11)
            .uri("/")
            .header("Transfer-encoding", "chunked")
            .body(b"1\r\na\r\na\r\nabcdefghij\r\n0\r\n\r\n".to_vec())
            .unwrap();
        let expected_bytes = b"POST / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n1\r\na\r\na\r\nabcdefghij\r\n0\r\n\r\n";
        let mut dst = BytesMut::with_capacity(1000);

        server.encode(request, &mut dst).unwrap();

        assert_eq!(expected_bytes.to_vec(), dst.to_vec());
    }

    #[test]
    fn decode_post_chunked() {
        let mut client: HttpClient = HttpClient {};
        let mut buf: BytesMut = BytesMut::with_capacity(1000);
        let request = "POST / HTTP/1.1\r\nTransfer-encoding: chunked\r\n\r\n1\r\na\r\na\r\nabcdefghij\r\n0\r\n\r\n";
        buf.put(request);
        let expected = Request::builder()
            .method(http::Method::POST)
            .version(http::Version::HTTP_11)
            .uri("/")
            .header("Transfer-encoding", "chunked")
            .body(b"1\r\na\r\na\r\nabcdefghij\r\n0\r\n\r\n".to_vec())
            .unwrap();

        let request = client.decode(&mut buf).unwrap().unwrap();

        assert_request_equal(expected, request);
    }

    #[test]
    fn decode_post_chunked_not_finished() {
        let mut client: HttpClient = HttpClient {};
        let mut buf: BytesMut = BytesMut::with_capacity(1000);
        let request = "POST / HTTP/1.1\r\nTransfer-encoding: chunked\r\n\r\n1\r\n";
        buf.put(request);

        let request = client.decode(&mut buf);

        assert!(request.is_ok());
        assert!(request.unwrap().is_none());
    }

    #[test]
    fn decode_post_content_length() {
        let mut client: HttpClient = HttpClient {};
        let mut buf: BytesMut = BytesMut::with_capacity(1000);
        let request = "POST / HTTP/1.1\r\nContent-length: 10\r\n\r\nabcdefgh\r\n";
        buf.put(request);
        let expected = Request::builder()
            .method(http::Method::POST)
            .version(http::Version::HTTP_11)
            .uri("/")
            .header("Content-length", "10")
            .body(b"abcdefgh\r\n".to_vec())
            .unwrap();

        let request = client.decode(&mut buf).unwrap().unwrap();

        assert_request_equal(expected, request);
    }

    #[test]
    fn encode_post_content_length() {
        let mut server: HttpServer = HttpServer {};
        let request = Request::builder()
            .method(http::Method::POST)
            .version(http::Version::HTTP_11)
            .uri("/")
            .header("Content-length", "10")
            .body(b"abcdefghij".to_vec())
            .unwrap();
        let expected_bytes = b"POST / HTTP/1.1\r\ncontent-length: 10\r\n\r\nabcdefghij";
        let mut dst: BytesMut = BytesMut::with_capacity(1000);

        server.encode(request, &mut dst).unwrap();

        assert_eq!(expected_bytes.to_vec(), dst.to_vec());
    }

    #[test]
    fn decode_not_finished_chunked() {
        let mut client: HttpClient = HttpClient {};
        let mut buf: BytesMut = BytesMut::with_capacity(1000);
        let request = "POST / HTTP/1.1\r\nTransfer-encoding: chunked\r\n\r\n1\r\na\r\n";
        buf.put(request);

        let request = client.decode(&mut buf);

        assert!(request.is_ok());
        assert!(request.unwrap().is_none());
    }

    #[test]
    fn decode_unfinished_headers() {
        let mut client: HttpClient = HttpClient {};
        let mut buf: BytesMut = BytesMut::with_capacity(1000);
        let request = "POST / HTTP/1.1\r\nTransfer";
        buf.put(request);

        let request = client.decode(&mut buf);

        assert!(request.is_ok());
        assert!(request.unwrap().is_none());
    }

    fn assert_request_equal(expected: Request<Vec<u8>>, actual: Request<Vec<u8>>) {
        assert_eq!(expected.uri(), actual.uri());
        assert_eq!(expected.version(), actual.version());
        assert_eq!(expected.method(), actual.method());
        assert_eq!(expected.body(), actual.body());
        for (k, v) in actual.headers().iter() {
            assert_eq!(
                expected
                    .headers()
                    .get(k)
                    .expect("Header missing from expected"),
                v
            );
        }
        for (k, v) in expected.headers().iter() {
            assert_eq!(
                actual.headers().get(k).expect("Header missing from actual"),
                v
            );
        }
    }
}
