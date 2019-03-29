extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate tokio;
extern crate tokio_io;
extern crate trust_dns;

use std::net::SocketAddr;

use tokio::io;
use tokio::net::TcpListener;
use tokio::prelude::*;

mod logger;

fn main() -> Result<(), Box<std::error::Error>> {
  logger::init(false, 2, prism::PRISM_NAME);
  info!("{}, {}", prism::PRISM_NAME, prism::PRISM_VERSION);

  let addr = "127.0.0.1:8080".to_string().parse::<SocketAddr>().unwrap();

  let socket = TcpListener::bind(&addr)?;
  info!("listening on: {}", addr);

  let server = socket
    .incoming()
    .map_err(|e| error!("failed to accept socket; error = {:?}", e))
    .for_each(move |socket| {
      let (reader, writer) = socket.split();
      let amount = io::copy(reader, writer);

      let msg = amount.then(move |result| {
        match result {
          Ok((amount, _, _)) => info!("wrote {} bytes", amount),
          Err(e) => info!("error: {}", e),
        }
        Ok(())
      });

      tokio::spawn(msg)
    });
  tokio::run(server);
  Ok(())
}
