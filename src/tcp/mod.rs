#![allow(unused, unused_variables)]

use crate::ip_stack::{IpStack, NetworkTuple, TransportPacket, UNSPECIFIED_ADDR};
use crate::tcp::sys::TcpStreamTask;
use crate::tcp::tcb::Tcb;
use bytes::{Buf, BytesMut};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::TcpFlags::{ACK, RST, SYN};
use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::net::SocketAddr;
use std::ops::Add;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Notify;
use tokio_util::sync::PollSender;

pub use tcb::TcpConfig;
mod sys;
mod tcb;
mod tcp_ofo_queue;

pub struct TcpListener {
    ip_stack: IpStack,
    packet_receiver: Receiver<TransportPacket>,
    local_addr: SocketAddr,
    tcb_map: HashMap<NetworkTuple, Tcb>,
}

pub struct TcpStream {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    read: TcpStreamReadHalf,
    write: TcpStreamWriteHalf,
}
pub struct TcpStreamReadHalf {
    last_buf: Option<BytesMut>,
    payload_receiver: Receiver<BytesMut>,
}
pub struct TcpStreamWriteHalf {
    mss: usize,
    payload_sender: PollSender<BytesMut>,
}

impl TcpListener {
    pub async fn bind_all(ip_stack: IpStack) -> io::Result<Self> {
        Self::bind(ip_stack, UNSPECIFIED_ADDR).await
    }
    pub async fn bind(ip_stack: IpStack, local_addr: SocketAddr) -> io::Result<Self> {
        let (packet_sender, packet_receiver) = channel(ip_stack.config.tcp_syn_channel_size);
        ip_stack.add_tcp_listener(local_addr, packet_sender)?;
        Ok(Self {
            ip_stack,
            packet_receiver,
            local_addr,
            tcb_map: Default::default(),
        })
    }
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        loop {
            if let Some(packet) = self.packet_receiver.recv().await {
                let network_tuple = &packet.network_tuple;
                if let Some(v) = self.ip_stack.inner.tcp_stream_map.get(network_tuple).as_deref().cloned() {
                    // If a TCP stream has already been generated, hand it over to the corresponding stream
                    _ = v.send(packet).await;
                    continue;
                }
                let Some(tcp_packet) = pnet_packet::tcp::TcpPacket::new(&packet.buf) else {
                    return Err(Error::new(io::ErrorKind::InvalidInput, "not tcp"));
                };
                let local_addr = network_tuple.dst;
                let peer_addr = network_tuple.src;
                if tcp_packet.get_flags() & SYN == SYN {
                    // LISTEN -> SYN_RECEIVED
                    let tcp_config = self.ip_stack.config.tcp_config;
                    let mut tcb = Tcb::new_listen(local_addr, peer_addr, tcp_config);
                    if let Some(relay_packet) = tcb.try_syn_received(&tcp_packet) {
                        self.ip_stack.send_packet(relay_packet).await?;
                        self.tcb_map.insert(*network_tuple, tcb);
                    }
                } else if let Some(tcb) = self.tcb_map.get_mut(network_tuple) {
                    // SYN_RECEIVED -> ESTABLISHED
                    if tcb.try_syn_received_to_established(packet.buf) {
                        let tcb = self.tcb_map.remove(network_tuple).unwrap();
                        return Ok((TcpStream::new(self.ip_stack.clone(), tcb)?, peer_addr));
                    }
                    if tcb.is_close() {
                        self.tcb_map.remove(network_tuple).unwrap();
                    }
                } else if tcp_packet.get_flags() & RST != RST {
                    let data = tcb::create_transport_packet_raw(
                        &local_addr,
                        &peer_addr,
                        0,
                        tcp_packet.get_sequence().wrapping_add(1),
                        0,
                        RST | ACK,
                        &[],
                    );
                    self.ip_stack.send_packet(data).await?;
                }
            } else {
                return Err(Error::from(io::ErrorKind::UnexpectedEof));
            }
        }
    }
}

impl TcpStream {
    pub async fn connect(ip_stack: IpStack, src: SocketAddr, dest: SocketAddr) -> io::Result<Self> {
        Self::connect0(ip_stack, src, dest).await
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
    pub fn split(self) -> (TcpStreamWriteHalf, TcpStreamReadHalf) {
        (self.write, self.read)
    }
}

impl TcpStream {
    pub(crate) async fn connect0(ip_stack: IpStack, local_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<Self> {
        let (payload_sender_w, payload_receiver_w) = channel(ip_stack.config.tcp_channel_size);
        let (payload_sender, payload_receiver) = channel(ip_stack.config.tcp_channel_size);
        let (packet_sender, packet_receiver) = channel(ip_stack.config.tcp_channel_size);
        let network_tuple = NetworkTuple::new(peer_addr, local_addr, IpNextHeaderProtocols::Tcp);
        ip_stack.add_tcp_socket(network_tuple, packet_sender)?;
        let mut tcp_config = ip_stack.config.tcp_config;
        if tcp_config.mss.is_none() {
            tcp_config.mss.replace(ip_stack.config.mtu - tcb::IP_TCP_HEADER_LEN as u16);
        }
        let tcb = Tcb::new_listen(local_addr, peer_addr, ip_stack.config.tcp_config);
        let mut stream_task = TcpStreamTask::new(tcb, ip_stack, payload_sender, payload_receiver_w, packet_receiver);
        stream_task.connect().await?;
        let mss = stream_task.mss() as usize;
        tokio::spawn(async move {
            if let Err(e) = stream_task.run().await {
                log::warn!("stream_task run {local_addr}->{peer_addr}: {e:?}")
            }
        });
        let read = TcpStreamReadHalf {
            last_buf: None,
            payload_receiver,
        };
        let write = TcpStreamWriteHalf {
            mss,
            payload_sender: PollSender::new(payload_sender_w),
        };
        let stream = Self {
            local_addr,
            peer_addr,
            read,
            write,
        };
        Ok(stream)
    }
    pub(crate) fn new0(ip_stack: IpStack, tcb: Tcb) -> io::Result<(Self, TcpStreamTask)> {
        let peer_addr = tcb.peer_addr();
        let local_addr = tcb.local_addr();
        let (payload_sender_w, payload_receiver_w) = channel(ip_stack.config.tcp_channel_size);
        let (payload_sender, payload_receiver) = channel(ip_stack.config.tcp_channel_size);
        let (packet_sender, packet_receiver) = channel(ip_stack.config.tcp_channel_size);
        let network_tuple = NetworkTuple::new(peer_addr, local_addr, IpNextHeaderProtocols::Tcp);
        ip_stack.add_tcp_socket(network_tuple, packet_sender)?;
        let mss = tcb.mss() as usize;
        let mut stream_task = TcpStreamTask::new(tcb, ip_stack, payload_sender, payload_receiver_w, packet_receiver);

        let read = TcpStreamReadHalf {
            last_buf: None,
            payload_receiver,
        };
        let write = TcpStreamWriteHalf {
            mss,
            payload_sender: PollSender::new(payload_sender_w),
        };
        let stream = Self {
            local_addr,
            peer_addr,
            read,
            write,
        };
        Ok((stream, stream_task))
    }
    pub(crate) fn new(ip_stack: IpStack, tcb: Tcb) -> io::Result<Self> {
        let peer_addr = tcb.peer_addr();
        let local_addr = tcb.local_addr();
        let (stream, mut stream_task) = Self::new0(ip_stack, tcb)?;
        tokio::spawn(async move {
            if let Err(e) = stream_task.run().await {
                log::warn!("stream_task run {local_addr}->{peer_addr}: {e:?}")
            }
        });
        Ok(stream)
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}
impl AsyncRead for TcpStreamReadHalf {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if let Some(p) = self.last_buf.as_mut() {
            let len = buf.remaining().min(p.len());
            buf.put_slice(&p[..len]);
            p.advance(len);
            if p.is_empty() {
                self.last_buf.take();
            }
            return Poll::Ready(Ok(()));
        }
        let poll = self.payload_receiver.poll_recv(cx);
        match poll {
            Poll::Ready(None) => Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof))),
            Poll::Ready(Some(mut p)) => {
                if p.is_empty() {
                    self.payload_receiver.close();
                    return Poll::Ready(Ok(()));
                }
                let len = buf.remaining().min(p.len());
                buf.put_slice(&p[..len]);
                p.advance(len);
                if !p.is_empty() {
                    self.last_buf.replace(p);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl AsyncWrite for TcpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}
impl AsyncWrite for TcpStreamWriteHalf {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        if buf.is_empty() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
        }
        match self.payload_sender.poll_reserve(cx) {
            Poll::Ready(Ok(_)) => {
                let len = buf.len().min(self.mss * 10);
                let buf = &buf[..len];
                match self.payload_sender.send_item(buf.into()) {
                    Ok(_) => {}
                    Err(_) => return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero))),
                };
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.payload_sender.close();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.ip_stack.remove_tcp_listener(&self.local_addr)
    }
}
