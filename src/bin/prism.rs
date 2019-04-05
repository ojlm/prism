extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate tokio;
#[macro_use]
extern crate tokio_core;
extern crate tokio_io;
extern crate trust_dns;

use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;
use std::str;
use std::time::Duration;

use futures::future;
use futures::{Async, Future, Poll, Stream};
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::{Core, Handle, Timeout};
use tokio_io::io::{read_exact, write_all, Window};
use trust_dns::client::{BasicClientHandle, ClientFuture, ClientHandle};
use trust_dns::op::{Message, ResponseCode};
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use trust_dns::udp::UdpClientStream;

mod logger;

fn main() {
  logger::init(false, 2, prism::PRISM_NAME);
  info!("{}, {}", prism::PRISM_NAME, prism::PRISM_VERSION);

  let addr = "127.0.0.1:8080".to_string().parse::<SocketAddr>().unwrap();

  let mut lp = Core::new().unwrap();
  let buffer = Rc::new(RefCell::new(vec![0; 64 * 1024]));
  let handler = lp.handle();
  let listener = TcpListener::bind(&addr, &handler).unwrap();

  let dns = "8.8.8.8:53".parse().unwrap();
  let (stream, sender) = UdpClientStream::new(dns, handler.clone());
  let client = ClientFuture::new(stream, sender, handler.clone(), None);

  info!("listening for socks5 proxy connections on: {}", addr);
  let clients = listener.incoming().map(move |(socket, addr)| {
    (
      Client {
        buffer: buffer.clone(),
        dns: client.clone(),
        handle: handler.clone(),
      }
      .serve(socket),
      addr,
    )
  });
  let handle = lp.handle();
  let server = clients.for_each(|(client, addr)| {
    handle.spawn(client.then(move |res| {
      match res {
        Ok((a, b)) => info!("proxied {}/{} bytes for {}", a, b, addr),
        Err(e) => error!("error for {}: {}", addr, e),
      }
      future::ok(())
    }));
    Ok(())
  });

  lp.run(server).unwrap();
}

struct Client {
  buffer: Rc<RefCell<Vec<u8>>>,
  dns: BasicClientHandle,
  handle: Handle,
}

impl Client {
  fn serve(self, conn: TcpStream) -> Box<Future<Item = (u64, u64), Error = io::Error>> {
    Box::new(read_exact(conn, [0u8]).and_then(|(conn, buf)| match buf[0] {
      socks5::VERSION => self.serve_v5(conn),
      socks4::VERSION => self.serve_v4(conn),
      _ => Box::new(future::err(other("unknown version"))),
    }))
  }

  fn serve_v4(self, _conn: TcpStream) -> Box<Future<Item = (u64, u64), Error = io::Error>> {
    Box::new(future::err(other("unimplemented")))
  }

  // https://tools.ietf.org/html/rfc1928
  fn serve_v5(self, conn: TcpStream) -> Box<Future<Item = (u64, u64), Error = io::Error>> {
    // Negotiation for which authentication method will be used
    let num_methods = read_exact(conn, [0u8]);
    let authenticated = num_methods
      .and_then(|(conn, buf)| read_exact(conn, vec![0u8; buf[0] as usize]))
      .and_then(|(conn, buf)| {
        if buf.contains(&socks5::METHOD_NO_AUTH) {
          Ok(conn)
        } else {
          Err(other("no supported method given"))
        }
      });

    // Sends a METHOD selection message
    let part1 = authenticated.and_then(|conn| write_all(conn, [socks5::VERSION, socks5::METHOD_NO_AUTH]));

    // Request details
    let ack = part1.and_then(|(conn, _)| {
      read_exact(conn, [0u8]).and_then(|(conn, buf)| {
        if buf[0] == socks5::VERSION {
          Ok(conn)
        } else {
          Err(other("didn't confirm with v5 version"))
        }
      })
    });

    let command = ack.and_then(|conn| {
      read_exact(conn, [0u8]).and_then(|(conn, buf)| {
        if buf[0] == socks5::CMD_CONNECT {
          Ok(conn)
        } else {
          Err(other("unsupported command"))
        }
      })
    });

    let mut dns = self.dns.clone();
    let rsv = command.and_then(|c| read_exact(c, [0u8]).map(|c| c.0));
    let atyp = rsv.and_then(|c| read_exact(c, [0u8]));
    let addr = my_box(atyp.and_then(move |(c, buf)| {
      match buf[0] {
        socks5::ATYP_IPV4 => my_box(read_exact(c, [0u8; 6]).map(|(c, buf)| {
          let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
          let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
          let addr = SocketAddrV4::new(addr, port);
          (c, SocketAddr::V4(addr))
        })),
        socks5::ATYP_IPV6 => my_box(read_exact(c, [0u8; 18]).map(|(conn, buf)| {
          let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
          let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
          let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
          let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
          let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
          let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
          let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
          let h = ((buf[14] as u16) << 8) | (buf[15] as u16);
          let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
          let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
          let addr = SocketAddrV6::new(addr, port, 0, 0);
          (conn, SocketAddr::V6(addr))
        })),
        socks5::ATYP_DOMAIN => my_box(
          read_exact(c, [0u8])
            .and_then(|(conn, buf)| read_exact(conn, vec![0u8; buf[0] as usize + 2]))
            .and_then(move |(conn, buf)| {
              let (name, port) = match name_port(&buf) {
                Ok(UrlHost::Name(name, port)) => (name, port),
                Ok(UrlHost::Addr(addr)) => {
                  return my_box(future::ok((conn, addr)));
                }
                Err(e) => return my_box(future::err(e)),
              };

              let ipv4 = dns
                .query(name, DNSClass::IN, RecordType::A)
                .map_err(|e| other(&format!("dns error: {}", e)))
                .and_then(move |r| get_addr(r, port));

              my_box(ipv4.map(|addr| (conn, addr)))
            }),
        ),
        n => {
          let msg = format!("unknown ATYP received: {}", n);
          my_box(future::err(other(&msg)))
        }
      }
    }));

    let handle = self.handle.clone();
    let connected = my_box(addr.and_then(move |(c, addr)| {
      debug!("proxying to {}", addr);
      TcpStream::connect(&addr, &handle).then(move |c2| Ok((c, c2, addr)))
    }));

    let handshake_finish = my_box(connected.and_then(|(c1, c2, addr)| {
      // +----+-----+-------+------+----------+----------+
      // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
      // +----+-----+-------+------+----------+----------+
      // | 1  |  1  | X'00' |  1   | Variable |    2     |
      // +----+-----+-------+------+----------+----------+
      let mut resp = [0u8; 32];

      // VER = protocol version
      resp[0] = 5;

      // REP - Reply field:
      // X'00' succeeded
      // X'01' general SOCKS server failure
      // X'02' connection not allowed by rule set
      // X'03' Network unreachable
      // X'04' Host unreachable
      // X'05' Connection refused
      // X'06' TTL expired
      // X'07' Command not supported
      // X'08' Address type not supported
      // X'09' to X'FF' unassigned
      resp[1] = match c2 {
        Ok(..) => 0,
        Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
        Err(..) => 1,
      };

      // ATYP, BND.ADDR, and BND.PORT
      let addr = match c2.as_ref().map(|r| r.local_addr()) {
        Ok(Ok(addr)) => addr,
        Ok(Err(..)) | Err(..) => addr,
      };
      let pos = match addr {
        SocketAddr::V4(ref a) => {
          resp[3] = socks5::ATYP_IPV4;
          resp[4..8].copy_from_slice(&a.ip().octets()[..]);
          8
        }
        SocketAddr::V6(ref a) => {
          resp[3] = socks5::ATYP_IPV6;
          let mut pos = 4;
          for &segment in a.ip().segments().iter() {
            resp[pos] = (segment >> 8) as u8;
            resp[pos + 1] = segment as u8;
            pos += 2;
          }
          pos
        }
      };
      resp[pos] = (addr.port() >> 8) as u8;
      resp[pos + 1] = addr.port() as u8;

      let mut w = Window::new(resp);
      w.set_end(pos + 2);
      write_all(c1, w).and_then(|(c1, _)| c2.map(|c2| (c1, c2)))
    }));

    let timeout = Timeout::new(Duration::new(10, 0), &self.handle).unwrap();
    let pair = my_box(handshake_finish.map(Ok).select(timeout.map(Err)).then(|res| match res {
      Ok((Ok(pair), _timeout)) => Ok(pair),
      Ok((Err(()), _handshake)) => Err(other("timeout during handshake")),
      Err((e, _other)) => Err(e),
    }));

    let buffer = self.buffer.clone();
    my_box(pair.and_then(|(c1, c2)| {
      let c1 = Rc::new(c1);
      let c2 = Rc::new(c2);

      let half1 = Transfer::new(c1.clone(), c2.clone(), buffer.clone());
      let half2 = Transfer::new(c2, c1, buffer);
      half1.join(half2)
    }))
  }
}

fn my_box<F: Future + 'static>(f: F) -> Box<Future<Item = F::Item, Error = F::Error>> {
  Box::new(f)
}

struct Transfer {
  reader: Rc<TcpStream>,
  writer: Rc<TcpStream>,
  // The shared global buffer that all connections on our server using
  buf: Rc<RefCell<Vec<u8>>>,
  // The number of bytes we've written so far.
  amt: u64,
}

impl Transfer {
  fn new(reader: Rc<TcpStream>, writer: Rc<TcpStream>, buffer: Rc<RefCell<Vec<u8>>>) -> Transfer {
    Transfer {
      reader,
      writer,
      buf: buffer,
      amt: 0,
    }
  }
}

impl Future for Transfer {
  type Item = u64;
  type Error = io::Error;

  fn poll(&mut self) -> Poll<u64, io::Error> {
    let mut buffer = self.buf.borrow_mut();

    loop {
      let read_ready = self.reader.poll_read().is_ready();
      let write_ready = self.writer.poll_write().is_ready();
      if !read_ready || !write_ready {
        return Ok(Async::NotReady);
      }

      let n = try_nb!((&*self.reader).read(&mut buffer));
      if n == 0 {
        self.writer.shutdown(Shutdown::Write)?;
        return Ok(self.amt.into());
      }
      self.amt += n as u64;

      let m = (&*self.writer).write(&buffer[..n])?;
      assert_eq!(n, m);
    }
  }
}

fn other(desc: &str) -> io::Error {
  io::Error::new(io::ErrorKind::Other, desc)
}

enum UrlHost {
  Name(Name, u16),
  Addr(SocketAddr),
}

fn name_port(addr_buf: &[u8]) -> io::Result<UrlHost> {
  let hostname = &addr_buf[..addr_buf.len() - 2];
  let hostname = str::from_utf8(hostname).map_err(|_e| other("hostname buffer provided was not valid utf-8"))?;
  let pos = addr_buf.len() - 2;
  let port = ((addr_buf[pos] as u16) << 8) | (addr_buf[pos + 1] as u16);

  if let Ok(ip) = hostname.parse() {
    return Ok(UrlHost::Addr(SocketAddr::new(ip, port)));
  }
  let name =
    Name::parse(hostname, Some(&Name::root())).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

  Ok(UrlHost::Name(name, port))
}

// Extracts the first IP address from the response
fn get_addr(response: Message, port: u16) -> io::Result<SocketAddr> {
  if response.get_response_code() != ResponseCode::NoError {
    return Err(other("resolution failed"));
  }
  let addr = response
    .get_answers()
    .iter()
    .filter_map(|ans| match *ans.get_rdata() {
      RData::A(addr) => Some(IpAddr::V4(addr)),
      RData::AAAA(addr) => Some(IpAddr::V6(addr)),
      _ => None,
    })
    .next();
  match addr {
    Some(addr) => Ok(SocketAddr::new(addr, port)),
    None => Err(other("no address records in response")),
  }
}

#[allow(dead_code)]
mod socks4 {
  pub const VERSION: u8 = 4;

  pub const CMD_CONNECT: u8 = 1;
  pub const CMD_BIND: u8 = 2;
}

#[allow(dead_code)]
mod socks5 {
  pub const VERSION: u8 = 5;

  pub const METHOD_NO_AUTH: u8 = 0;
  pub const METHOD_GSSAPI: u8 = 1;
  pub const METHOD_USER_PASS: u8 = 2;

  pub const CMD_CONNECT: u8 = 1;
  pub const CMD_BIND: u8 = 2;
  pub const CMD_UDP_ASSOCIATE: u8 = 3;

  pub const ATYP_IPV4: u8 = 1;
  pub const ATYP_DOMAIN: u8 = 3;
  pub const ATYP_IPV6: u8 = 4;
}
