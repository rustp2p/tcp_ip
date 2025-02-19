use std::io;
use std::net::IpAddr;
use std::ops::Deref;

use pnet_packet::ip::IpNextHeaderProtocols;

use crate::ip::IpSocket;
use crate::ip_stack::{IpStack, UNSPECIFIED_ADDR_V4, UNSPECIFIED_ADDR_V6};

pub struct IcmpSocket {
    raw_ip_socket: IpSocket,
}
#[cfg(feature = "global-ip-stack")]
impl IcmpSocket {
    pub async fn bind_all() -> io::Result<Self> {
        Self::bind(UNSPECIFIED_ADDR_V4.ip()).await
    }
    pub async fn bind(local_ip: IpAddr) -> io::Result<Self> {
        if local_ip.is_ipv6() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "need to use IcmpV6Socket"));
        }
        let ip_stack = IpStack::get()?;
        let raw_ip_socket = IpSocket::bind0(
            ip_stack.config.icmp_channel_size,
            Some(IpNextHeaderProtocols::Icmp),
            ip_stack,
            Some(local_ip),
        )
        .await?;
        Ok(Self { raw_ip_socket })
    }
}
#[cfg(not(feature = "global-ip-stack"))]
impl IcmpSocket {
    pub async fn bind_all(ip_stack: IpStack) -> io::Result<Self> {
        Self::bind(ip_stack, UNSPECIFIED_ADDR_V4.ip()).await
    }
    pub async fn bind(ip_stack: IpStack, local_ip: IpAddr) -> io::Result<Self> {
        if local_ip.is_ipv6() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "need to use IcmpV6Socket"));
        }
        let raw_ip_socket = IpSocket::bind0(
            ip_stack.config.icmp_channel_size,
            Some(IpNextHeaderProtocols::Icmp),
            ip_stack,
            Some(local_ip),
        )
        .await?;
        Ok(Self { raw_ip_socket })
    }
}

impl Deref for IcmpSocket {
    type Target = IpSocket;

    fn deref(&self) -> &Self::Target {
        &self.raw_ip_socket
    }
}

pub struct IcmpV6Socket {
    raw_ip_socket: IpSocket,
}
#[cfg(feature = "global-ip-stack")]
impl IcmpV6Socket {
    pub async fn bind_all() -> io::Result<Self> {
        Self::bind(UNSPECIFIED_ADDR_V6.ip()).await
    }
    pub async fn bind(local_ip: IpAddr) -> io::Result<Self> {
        if local_ip.is_ipv4() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "need to use IcmpSocket"));
        }
        let ip_stack = IpStack::get()?;
        let raw_ip_socket = IpSocket::bind0(
            ip_stack.config.icmp_channel_size,
            Some(IpNextHeaderProtocols::Icmpv6),
            ip_stack,
            Some(local_ip),
        )
        .await?;
        Ok(Self { raw_ip_socket })
    }
}
#[cfg(not(feature = "global-ip-stack"))]
impl IcmpV6Socket {
    pub async fn bind_all(ip_stack: IpStack) -> io::Result<Self> {
        Self::bind(ip_stack, UNSPECIFIED_ADDR_V6.ip()).await
    }
    pub async fn bind(ip_stack: IpStack, local_ip: IpAddr) -> io::Result<Self> {
        if local_ip.is_ipv4() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "need to use IcmpSocket"));
        }
        let raw_ip_socket = IpSocket::bind0(
            ip_stack.config.icmp_channel_size,
            Some(IpNextHeaderProtocols::Icmpv6),
            ip_stack,
            Some(local_ip),
        )
        .await?;
        Ok(Self { raw_ip_socket })
    }
}

impl Deref for IcmpV6Socket {
    type Target = IpSocket;

    fn deref(&self) -> &Self::Target {
        &self.raw_ip_socket
    }
}
