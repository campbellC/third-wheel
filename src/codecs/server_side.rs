/* Copyright (c) 2019 Tokio Contributors

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
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE. */

// Code borrowed from https://github.com/tokio-rs/tokio/blob/master/examples/tinyhttp.rs
use tokio::codec::{Decoder, Encoder};
use bytes::BytesMut;
use http::{header::HeaderValue, Request, Response, StatusCode};
use std::{env, error::Error, fmt, io};
use std::str::FromStr;
use super::client_side::BodyParser;

pub struct HttpServerSide;

//TODO: modify this for different versions of HTTP1?
//TODO: modify this to just write the actual response given to it
impl Encoder for HttpServerSide {
    type Item = Response<Vec<u8>>;
    type Error = io::Error;

    fn encode(&mut self, item: Response<Vec<u8>>, dst: &mut BytesMut) -> io::Result<()> {
        use std::fmt::Write;

        write!(
            BytesWrite(dst),
            "\
             HTTP/1.1 {}\r\n\
             ",
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

/// Implementation of decoding an HTTP request from the bytes we've read so far.
/// This leverages the `httparse` crate to do the actual parsing and then we use
/// that information to construct an instance of a `http::Request` object,
/// trying to avoid allocations where possible.
impl Decoder for HttpServerSide {
    type Item = Request<Vec<u8>>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Request<Vec<u8>>>> {
        // TODO: we should grow this headers array if parsing fails and asks
        //       for more headers
        let mut headers = [None; 16];
        let (method, path, version, amt, body_parser) = {
            let mut parsed_headers = [httparse::EMPTY_HEADER; 16];
            let mut r = httparse::Request::new(&mut parsed_headers);
            let status = r.parse(src).map_err(|e| {
                let msg = format!("failed to parse http request: {:?}", e);
                io::Error::new(io::ErrorKind::Other, msg)
            })?;

            let amt = match status {
                httparse::Status::Complete(amt) => amt,
                //TODO: Looking at httparse source code I'm not sure this will properly wait for the full chunks or content
                httparse::Status::Partial => return Ok(None),
            };

            let toslice = |a: &[u8]| {
                let start = a.as_ptr() as usize - src.as_ptr() as usize;
                assert!(start < src.len());
                (start, start + a.len())
            };

            let mut body_parser: BodyParser = BodyParser::OTHER;
            for (i, header) in r.headers.iter().enumerate() {
                if header.name.to_lowercase() == "transfer-encoding" {
                    assert!(header.value == b"chunked");
                    body_parser = BodyParser::CHUNKED;
                } else if header.name.to_lowercase() == "content-length" {
                    body_parser = BodyParser::CONTENT_LENGTH(String::from_utf8(header.value.to_vec()).unwrap().parse().unwrap())
                }
                let k = toslice(header.name.as_bytes());
                let v = toslice(header.value);
                headers[i] = Some((k, v));
            }

            (
                toslice(r.method.unwrap().as_bytes()),
                toslice(r.path.unwrap().as_bytes()),
                r.version.unwrap(),
                amt,
                body_parser,
            )
        };
        if version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "only HTTP/1.1 accepted",
            ));
        }
        if !body_parser.is_complete(&src[amt..]) { return Ok(None); }
        let data = src.split_to(amt).freeze();
        let mut ret = Request::builder();
        ret.method(&data[method.0..method.1]);
        let uri = http::Uri::from_str(&String::from_utf8(data.slice(path.0, path.1).to_vec()).unwrap());
        dbg!(&uri);
        if ret.method_ref().unwrap() == http::Method::CONNECT {
            ret.uri(uri.unwrap());
        } else {
            ret.uri(uri.unwrap().path());
        }
        ret.version(http::Version::HTTP_11);
        for header in headers.iter() {
            let (k, v) = match *header {
                Some((ref k, ref v)) => (k, v),
                None => break,
            };
            let value = unsafe { HeaderValue::from_shared_unchecked(data.slice(v.0, v.1)) };
            let header_name = String::from_utf8(data[k.0..k.1].to_vec()).unwrap();
            if header_name.to_lowercase() == "proxy-connection" {continue;}
            ret.header(&data[k.0..k.1], value);
        }
        let req = ret
            .body(src.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Some(req))
    }
}

