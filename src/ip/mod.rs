use std::io;
use std::net::{IpAddr, SocketAddr};

use crate::ip_stack::{check_ip, default_ip, IpStack, NetworkTuple, TransportPacket};
use bytes::BytesMut;
pub use pnet_packet::ip::IpNextHeaderProtocol;
pub use pnet_packet::ip::IpNextHeaderProtocols;

/// Internally handles the splitting and reassembly of IP fragmentation.
/// The read and write operations of Ipv4Socket do not include the IP header.
/// For reading and writing, only the upper-layer protocol data of IP needs to be considered.
pub struct IpSocket {
    protocol: Option<IpNextHeaderProtocol>,
    ip_stack: IpStack,
    packet_receiver: flume::Receiver<TransportPacket>,
    local_addr: Option<SocketAddr>,
}

impl IpSocket {
    pub async fn bind_all(protocol: Option<IpNextHeaderProtocol>, ip_stack: IpStack) -> io::Result<Self> {
        Self::bind0(ip_stack.config.ip_channel_size, protocol, ip_stack, None).await
    }
    pub async fn bind(protocol: Option<IpNextHeaderProtocol>, ip_stack: IpStack, local_ip: IpAddr) -> io::Result<Self> {
        Self::bind0(ip_stack.config.ip_channel_size, protocol, ip_stack, Some(local_ip)).await
    }
    pub(crate) async fn bind0(
        channel_size: usize,
        protocol: Option<IpNextHeaderProtocol>,
        ip_stack: IpStack,
        local_ip: Option<IpAddr>,
    ) -> io::Result<Self> {
        let local_addr = local_ip.map(|ip| SocketAddr::new(ip, 0));
        let (packet_sender, packet_receiver) = flume::bounded(channel_size);
        ip_stack.add_ip_socket(protocol, local_addr, packet_sender)?;
        Ok(Self {
            protocol,
            ip_stack,
            packet_receiver,
            local_addr,
        })
    }
}

impl IpSocket {
    pub fn local_ip(&self) -> io::Result<IpAddr> {
        self.local_addr
            .map(|v| v.ip())
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, IpAddr)> {
        let (len, src, _dst) = self.recv_from_to(buf).await?;
        Ok((len, src))
    }
    pub async fn send_to(&self, buf: &[u8], addr: IpAddr) -> io::Result<usize> {
        let from = if let Some(from) = self.local_addr {
            from.ip()
        } else {
            default_ip(addr.is_ipv4())
        };
        self.send_from_to(buf, from, addr).await
    }
    pub async fn recv_from_to(&self, buf: &mut [u8]) -> io::Result<(usize, IpAddr, IpAddr)> {
        let (len, _p, src, dst) = self.recv_protocol_from_to(buf).await?;
        Ok((len, src, dst))
    }
    pub async fn recv_protocol_from_to(&self, buf: &mut [u8]) -> io::Result<(usize, IpNextHeaderProtocol, IpAddr, IpAddr)> {
        let Ok(packet) = self.packet_receiver.recv_async().await else {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        };

        let len = packet.buf.len();
        if buf.len() < len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("buf too short: {}<{len}", buf.len()),
            ));
        }
        buf[..len].copy_from_slice(&packet.buf);
        Ok((
            len,
            packet.network_tuple.protocol,
            packet.network_tuple.src.ip(),
            packet.network_tuple.dst.ip(),
        ))
    }
    pub async fn send_from_to(&self, buf: &[u8], src: IpAddr, dst: IpAddr) -> io::Result<usize> {
        let Some(protocol) = self.protocol else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "need to specify protocol"));
        };
        self.send_protocol_from_to(buf, protocol, src, dst).await
    }
    pub async fn send_protocol_from_to(
        &self,
        buf: &[u8],
        protocol: IpNextHeaderProtocol,
        mut src: IpAddr,
        dst: IpAddr,
    ) -> io::Result<usize> {
        if let Some(p) = self.protocol {
            if p != protocol {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "inconsistent protocol"));
            }
        }
        if buf.len() > u16::MAX as usize - 8 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "buf too long"));
        }
        if src.is_ipv4() != dst.is_ipv4() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "address error"));
        }
        check_ip(dst)?;
        if let Err(e) = check_ip(src) {
            if let Some(v) = self.ip_stack.routes().route(dst) {
                src = v;
            } else {
                Err(e)?
            }
        }
        let data: BytesMut = buf.into();
        let src = SocketAddr::new(src, 0);
        let dst = SocketAddr::new(dst, 0);
        let network_tuple = NetworkTuple::new(src, dst, protocol);

        let packet = TransportPacket::new(data, network_tuple);
        if self.ip_stack.inner.packet_sender.send(packet).await.is_err() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Ok(buf.len())
    }
}
impl Drop for IpSocket {
    fn drop(&mut self) {
        self.ip_stack.remove_ip_socket(self.protocol, self.local_addr);
    }
}
