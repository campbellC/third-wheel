use tokio::codec::Encoder;
use http::Request;
use std::{env, error::Error, fmt, io};
use bytes::BytesMut;
use tokio::codec::Decoder;
use http::Response;
use http::HeaderValue;
use httparse::parse_chunk_size;
use httparse::Status;
use crate::codecs::client_side::BodyParser::OTHER;

pub struct HttpClientSide;

impl Encoder for HttpClientSide {
    type Item = Request<Vec<u8>>;
    type Error = io::Error;

    fn encode(&mut self, item: Request<Vec<u8>>, dst: &mut BytesMut) -> io::Result<()> {
        use std::fmt::Write;
        write!(
            BytesWrite(dst),
            "\
             {} {} {:?}\r\n\
             ",
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

        if item.body().len() != 0 {
            dst.extend_from_slice(item.body());
            dst.extend_from_slice(b"\r\n\r\n");
        } else {
            dst.extend_from_slice(b"\r\n");
        }
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

#[derive(Debug)]
pub(super) enum BodyParser {
    CHUNKED,
    CONTENT_LENGTH(usize),
    OTHER,
}

impl BodyParser {
    pub(super) fn is_complete(&self, bytes: &[u8]) -> bool {
        match self {
            &Self::CHUNKED => {
                let mut current: usize = 0;
                loop {
                    match parse_chunk_size(&bytes[current..]) {
                        Err(_) | Ok(Status::Partial) => return false,
                        Ok(Status::Complete((n, m))) => {
                            let m = m as usize;
                            if m == 0 {
                                return true;
                            }
                            else if current + n + m > bytes.len() {
                                return false;
                            } else {
                                current += n + m;
                            }
                        }
                    };
                }
            }
            &Self::CONTENT_LENGTH(length) => {
                return if length > bytes.len() { false } else { true };
            }
            &Self::OTHER => {return true;},
        }
    }
}

impl Decoder for HttpClientSide {
    type Item = Response<Vec<u8>>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Response<Vec<u8>>>> {
        // TODO: we should grow this headers array if parsing fails and asks
        //       for more headers
        let mut headers = [None; 16];
        let (status, reason, version, amt, body_parser) = {
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

            let mut body_parser: BodyParser = OTHER;
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
                r.code.unwrap(),
                toslice(r.reason.unwrap().as_bytes()),
                r.version.unwrap(),
                amt,
                body_parser,
            )
        };
        //TODO handle HTTP/1.0
        if version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("only HTTP/1.1 accepted but received {}", String::from_utf8(src.to_vec()).unwrap()),
            ));
        }
        if !body_parser.is_complete(&src[amt..]) { return Ok(None); }
        let data = src.split_to(amt).freeze();
        let mut ret = Response::builder();
        ret.status(status);
        //TODO: it seems that http crate doesn't let you set the reason-phrase. why and is this an issue?
        ret.version(http::Version::HTTP_11);
        for header in headers.iter() {
            let (k, v) = match *header {
                Some((ref k, ref v)) => (k, v),
                None => break,
            };
            let value = unsafe { HeaderValue::from_shared_unchecked(data.slice(v.0, v.1)) };
            ret.header(&data[k.0..k.1], value);
        }

        //TODO: handle non-empty body
        let response = ret.body(src.to_vec()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Some(response))
    }
}


