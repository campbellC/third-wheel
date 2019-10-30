use std::net::SocketAddr;

use tokio::prelude::*;
use tokio::net::TcpListener;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:8080".parse::<SocketAddr>()?;
    let mut listener = TcpListener::bind(&addr).await?;

    loop {
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buf = [0; 1024];
            let n = match socket.read(&mut buf).await {
                Ok(n) if n == 0 => return,
                Ok(n) => n,
                Err(e) => {
                    println!("Failed to read from socket; err = {:?}", e);
                    return;
                }
            };

            if let Err(e) = socket.write_all(&buf[0..n]).await {
                println!("failed to write to socket; err = {:?}", e);
                return;
            }
        });
    }
}
