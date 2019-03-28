extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate tokio;
extern crate tokio_io;
extern crate trust_dns;

use std::net::SocketAddr;

mod logger;

fn main() {
  logger::init(false, 2, prism::PRISM_NAME);
  info!("{}, {}", prism::PRISM_NAME, prism::PRISM_VERSION);

  let addr = "127.0.0.1:8080".to_string().parse::<SocketAddr>().unwrap();
  info!("socks listen on: {}", addr);
}
