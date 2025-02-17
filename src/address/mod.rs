use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

pub trait ToSocketAddr {
    fn to_addr(&self) -> io::Result<SocketAddr>;
}
impl ToSocketAddr for &SocketAddr {
    fn to_addr(&self) -> io::Result<SocketAddr> {
        Ok(**self)
    }
}
impl ToSocketAddr for SocketAddr {
    fn to_addr(&self) -> io::Result<SocketAddr> {
        Ok(*self)
    }
}
impl ToSocketAddr for &SocketAddrV4 {
    fn to_addr(&self) -> io::Result<SocketAddr> {
        Ok((**self).into())
    }
}
impl ToSocketAddr for SocketAddrV4 {
    fn to_addr(&self) -> io::Result<SocketAddr> {
        Ok((*self).into())
    }
}
impl ToSocketAddr for &SocketAddrV6 {
    fn to_addr(&self) -> io::Result<SocketAddr> {
        Ok((**self).into())
    }
}
impl ToSocketAddr for SocketAddrV6 {
    fn to_addr(&self) -> io::Result<SocketAddr> {
        Ok((*self).into())
    }
}
impl ToSocketAddr for &str {
    fn to_addr(&self) -> io::Result<SocketAddr> {
        self.parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))
    }
}
impl ToSocketAddr for &String {
    fn to_addr(&self) -> io::Result<SocketAddr> {
        self.as_str().to_addr()
    }
}
impl ToSocketAddr for String {
    fn to_addr(&self) -> io::Result<SocketAddr> {
        self.as_str().to_addr()
    }
}
