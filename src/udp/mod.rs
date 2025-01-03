use std::io;
use std::net::{IpAddr, SocketAddr};

use bytes::{BufMut, BytesMut};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::Packet;

use crate::ip_stack::{IpStack, NetworkTuple, TransportPacket};

pub struct UdpSocket {
    ip_stack: IpStack,
    packet_receiver: flume::Receiver<TransportPacket>,
    local_addr: Option<SocketAddr>,
}

impl UdpSocket {
    pub async fn bind_all(ip_stack: IpStack) -> io::Result<Self> {
        Self::bind0(ip_stack, None).await
    }
    pub async fn bind(ip_stack: IpStack, local_addr: SocketAddr) -> io::Result<Self> {
        Self::bind0(ip_stack, Some(local_addr)).await
    }
    async fn bind0(ip_stack: IpStack, local_addr: Option<SocketAddr>) -> io::Result<Self> {
        let (packet_sender, packet_receiver) = flume::bounded(ip_stack.config.udp_channel_size);
        ip_stack.add_socket(Some(IpNextHeaderProtocols::Udp), local_addr, packet_sender)?;
        Ok(Self {
            ip_stack,
            packet_receiver,
            local_addr,
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
                unreachable!()
            }
        };

        data[6..8].copy_from_slice(&checksum.to_be_bytes());
        let network_tuple = NetworkTuple::new(src, dst, IpNextHeaderProtocols::Udp);

        let packet = TransportPacket::new(data, network_tuple);
        self.ip_stack.send_packet(packet).await?;
        Ok(buf.len())
    }
}
impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.ip_stack.remove_socket(Some(IpNextHeaderProtocols::Udp), &self.local_addr);
    }
}
