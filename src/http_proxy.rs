use std::io::{Read, Write, Error, ErrorKind};
use std::net::SocketAddr;

use bytes::{BytesMut, BufMut};

use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::prelude::*;
use crate::SafeResult;
use tokio::codec::Framed;
use crate::codecs::server_side::HttpServerSide;
use http::Request;
use crate::codecs::client_side::HttpClientSide;

pub async fn run_http_proxy(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{}", port);
    println!("http proxy listening on {}", addr);
    let addr = addr.parse::<SocketAddr>()?;

    let mut listener = TcpListener::bind(&addr).await?;

    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut transport = Framed::new(stream, HttpServerSide);
            while let Some(request) = transport.next().await {
                match request {
                    Ok(request) => {
                        let host = String::from_utf8(Vec::from(request.headers().iter()
                            .filter(|x| x.0 == "Host")
                            .next()
                            .unwrap()
                            .1.as_bytes())).unwrap();
                        // This cannot be inlined due to a compiler issue
                        // https://github.com/rust-lang/rust/issues/64477
                        let target_address = format!("{}:80", host);
                        let target_stream = TcpStream::connect(target_address).await.unwrap();
                        let mut target_transport = Framed::new(target_stream, HttpClientSide);
                        target_transport.send(request).await.unwrap();
                        let response = target_transport.next().await.unwrap().expect("valid http response");
                        transport.send(response).await.unwrap();
                    }
                    Err(e) => {dbg!(e);},
                }
            }
        });
    }
}

