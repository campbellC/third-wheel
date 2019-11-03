use std::io::{Read, Write};
use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::prelude::*;

async fn get_target_details(socket: &mut TcpStream) -> Result<(String, bool), std::io::Error> {
    let mut buf = [0; 1024];
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    let _n = match socket.peek(&mut buf).await {
        Ok(n) => n,
        Err(e) => {
            println!("Failed to read from socket; err = {:?}", e);
            return Err(e);
        }
    };
    let _res = req.parse(&mut buf).unwrap();

    let host = String::from_utf8(Vec::from(req.headers.iter()
        .filter(|x| x.name == "Host")
        .next()
        //TODO I don't think we want unwrap here
        .unwrap()
        .value)).unwrap();
    return Ok((host, req.method.unwrap() == "CONNECT"));
}

pub async fn run_http_proxy(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{}", port);
    println!("http proxy listening on {}", addr);
    let addr = addr.parse::<SocketAddr>()?;

    let mut listener = TcpListener::bind(&addr).await?;

    loop {
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let (host, ssl) = get_target_details(&mut socket).await.unwrap();

            if ssl {
                //TODO: make this one work ;)
                unimplemented!();
            } else {
                let mut target_stream = std::net::TcpStream::connect(format!("{}:80", host)).unwrap();
                let mut buf = [0; 1024];
                let n = match socket.read(&mut buf).await {
                    Ok(n) if n == 0 => return,
                    Ok(n) => n,
                    Err(e) => {
                        println!("Failed to read from socket; err = {:?}", e);
                        return;
                    }
                };
                if let Err(e) = target_stream.write_all(&buf[0..n]) {
                    println!("failed to write to target socket; err = {:?}", e);
                    return;
                }
                loop {
                    let n = match target_stream.read(&mut buf) {
                        Ok(n) if n == 0 => return,
                        Ok(n) => n,
                        Err(e) => {
                            println!("Failed to read from socket; err = {:?}", e);
                            return;
                        }
                    };
                    if let Err(e) = socket.write_all(&buf[0..n]).await {
                        println!("failed to write to target socket; err = {:?}", e);
                        return;
                    };
                }
            }
        });
    }
}
