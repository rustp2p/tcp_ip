use std::io;
use std::net::{IpAddr, SocketAddr};

use bytes::{BufMut, BytesMut};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::Packet;

use crate::ip_stack::{check_addr, IpStack, NetworkTuple, TransportPacket};

/// A UDP socket.
///
/// UDP is "connectionless", unlike TCP. Meaning, regardless of what address you've bound to, a `UdpSocket`
/// is free to communicate with many different remotes. In tcp_ip there are basically two main ways to use `UdpSocket`:
///
/// * one to many: [`bind`](`UdpSocket::bind`) and use [`send_to`](`UdpSocket::send_to`)
///   and [`recv_from`](`UdpSocket::recv_from`) to communicate with many different addresses
/// * many to many: [`bind_all`](`UdpSocket::bind_all`) and use [`send_from_to`](`UdpSocket::send_from_to`)
///   and [`recv_from_to`](`UdpSocket::recv_from_to`) to communicate with many different addresses
/// * one to one: [`connect`](`UdpSocket::connect`) and associate with a single address, using [`send`](`UdpSocket::send`)
///   and [`recv`](`UdpSocket::recv`) to communicate only with that remote address
///
/// This type does not provide a `split` method, because this functionality
/// can be achieved by instead wrapping the socket in an [`Arc`]. Note that
/// you do not need a `Mutex` to share the `UdpSocket` — an `Arc<UdpSocket>`
/// is enough. This is because all of the methods take `&self` instead of
/// `&mut self`. Once you have wrapped it in an `Arc`, you can call
/// `.clone()` on the `Arc<UdpSocket>` to get multiple shared handles to the
/// same socket.
///
/// [`Arc`]: std::sync::Arc
pub struct UdpSocket {
    ip_stack: IpStack,
    packet_receiver: flume::Receiver<TransportPacket>,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
}

impl UdpSocket {
    pub async fn bind_all(ip_stack: IpStack) -> io::Result<Self> {
        Self::bind0(ip_stack, None, None).await
    }
    pub async fn bind(ip_stack: IpStack, local_addr: SocketAddr) -> io::Result<Self> {
        Self::bind0(ip_stack, Some(local_addr), None).await
    }
    async fn bind0(ip_stack: IpStack, local_addr: Option<SocketAddr>, peer_addr: Option<SocketAddr>) -> io::Result<Self> {
        let (packet_sender, packet_receiver) = flume::bounded(ip_stack.config.udp_channel_size);
        ip_stack.add_udp_socket(local_addr, peer_addr, packet_sender)?;
        Ok(Self {
            ip_stack,
            packet_receiver,
            local_addr,
            peer_addr,
        })
    }
}

impl UdpSocket {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (len, src, _dst) = self.recv_from_to(buf).await?;
        Ok((len, src))
    }
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let Some(from) = self.local_addr else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "need to specify source address"));
        };
        self.send_from_to(buf, from, addr).await
    }
    pub async fn recv_from_to(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        let Ok(packet) = self.packet_receiver.recv_async().await else {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        };
        let Some(udp_packet) = pnet_packet::udp::UdpPacket::new(&packet.buf) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not udp"));
        };
        let len = udp_packet.payload().len();
        if buf.len() < len {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "buf too short"));
        }
        buf[..len].copy_from_slice(udp_packet.payload());
        Ok((len, packet.network_tuple.src, packet.network_tuple.dst))
    }
    pub async fn send_from_to(&self, buf: &[u8], src: SocketAddr, dst: SocketAddr) -> io::Result<usize> {
        check_addr(src)?;
        check_addr(dst)?;
        if buf.len() > u16::MAX as usize - 8 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "buf too long"));
        }

        let mut data = BytesMut::with_capacity(8 + buf.len());

        data.put_u16(src.port());
        data.put_u16(dst.port());
        data.put_u16(8 + buf.len() as u16);
        // checksum
        data.put_u16(0);
        data.extend_from_slice(buf);

        let checksum = match (src.ip(), dst.ip()) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                pnet_packet::util::ipv4_checksum(&data, 3, &[], &src_ip, &dst_ip, IpNextHeaderProtocols::Udp)
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                pnet_packet::util::ipv6_checksum(&data, 3, &[], &src_ip, &dst_ip, IpNextHeaderProtocols::Udp)
            }
            (_, _) => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "address error"));
            }
        };

        data[6..8].copy_from_slice(&checksum.to_be_bytes());
        let network_tuple = NetworkTuple::new(src, dst, IpNextHeaderProtocols::Udp);

        let packet = TransportPacket::new(data, network_tuple);
        self.ip_stack.send_packet(packet).await?;
        Ok(buf.len())
    }
}
impl UdpSocket {
    pub async fn connect(ip_stack: IpStack, local_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<Self> {
        Self::bind0(ip_stack, Some(local_addr), Some(peer_addr)).await
    }
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let Some(from) = self.local_addr else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "need to specify source address"));
        };
        let Some(to) = self.peer_addr else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "need to specify destination address"));
        };
        self.send_from_to(buf, from, to).await
    }
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let (len, _src, _dst) = self.recv_from_to(buf).await?;
        Ok(len)
    }
}
impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.ip_stack.remove_udp_socket(self.local_addr, self.peer_addr);
    }
}
