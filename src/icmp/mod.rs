use std::io;
use std::net::IpAddr;
use std::ops::Deref;

use pnet_packet::ip::IpNextHeaderProtocols;

use crate::ip::Ipv4Socket;
use crate::ip_stack::{IpStack, UNSPECIFIED_ADDR};

pub struct IcmpSocket {
    raw_ip_socket: Ipv4Socket,
}

impl IcmpSocket {
    pub async fn bind_all(ip_stack: IpStack) -> io::Result<Self> {
        Self::bind(ip_stack, UNSPECIFIED_ADDR.ip()).await
    }
    pub async fn bind(ip_stack: IpStack, local_ip: IpAddr) -> io::Result<Self> {
        let raw_ip_socket = Ipv4Socket::bind0(ip_stack.config.icmp_channel_size, IpNextHeaderProtocols::Icmp, ip_stack, local_ip).await?;
        Ok(Self { raw_ip_socket })
    }
}

impl Deref for IcmpSocket {
    type Target = Ipv4Socket;

    fn deref(&self) -> &Self::Target {
        &self.raw_ip_socket
    }
}
