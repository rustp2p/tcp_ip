use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::TcpFlags::{ACK, RST, SYN};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{channel, Receiver};
use tokio_util::sync::PollSender;

pub use tcb::TcpConfig;

use crate::address::ToSocketAddr;
use crate::ip_stack::{check_ip, default_addr, validate_addr, BindAddr, IpStack, NetworkTuple, TransportPacket};
use crate::tcp::sys::{ReadNotify, TcpStreamTask};
use crate::tcp::tcb::Tcb;

mod sys;
mod tcb;
mod tcp_queue;

/// A TCP socket server, listening for connections.
/// You can accept a new connection by using the accept method.
/// # Example
///  ```no_run
/// use std::io;
///
/// async fn process_socket<T>(socket: T) {
///     // do work with socket here
/// }
///
/// #[tokio::main]
/// #[cfg(not(feature = "global-ip-stack"))]
/// async fn main() -> io::Result<()> {
///     let (ip_stack, _ip_stack_send, _ip_stack_recv) =
///             tcp_ip::ip_stack(tcp_ip::IpStackConfig::default())?;
///     // Read and write IP packets using _ip_stack_send and _ip_stack_recv
///     let src = "10.0.0.2:8080".parse().unwrap();
///     let mut listener = tcp_ip::tcp::TcpListener::bind(ip_stack.clone(),src).await?;
///
///     loop {
///         let (socket, _) = listener.accept().await?;
///         process_socket(socket).await;
///     }
/// }
/// ```
pub struct TcpListener {
    _bind_addr: Option<BindAddr>,
    ip_stack: IpStack,
    packet_receiver: Receiver<TransportPacket>,
    local_addr: Option<SocketAddr>,
    tcb_map: HashMap<NetworkTuple, Tcb>,
}

/// A TCP stream between a local and a remote socket.
///
/// # Example
/// ```no_run
/// #[tokio::main]
/// #[cfg(not(feature = "global-ip-stack"))]
/// async fn main() -> std::io::Result<()> {
///     // Connect to a peer
///     use tokio::io::AsyncWriteExt;
///     let (ip_stack, _ip_stack_send, _ip_stack_recv) =
///             tcp_ip::ip_stack(tcp_ip::IpStackConfig::default())?;
///     // Read and write IP packets using _ip_stack_send and _ip_stack_recv
///     let src = "10.0.0.2:8080".parse().unwrap();
///     let dst = "10.0.0.3:8080".parse().unwrap();
///     let mut stream = tcp_ip::tcp::TcpStream::bind(ip_stack.clone(),src)?
///             .connect(dst).await?;
///
///     // Write some data.
///     stream.write_all(b"hello world!").await?;
///
///     Ok(())
/// }
/// ```
pub struct TcpStream {
    bind_addr: Option<BindAddr>,
    ip_stack: Option<IpStack>,
    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    read: Option<TcpStreamReadHalf>,
    write: Option<TcpStreamWriteHalf>,
}

pub struct TcpStreamReadHalf {
    read_notify: ReadNotify,
    last_buf: Option<BytesMut>,
    payload_receiver: Receiver<BytesMut>,
}

pub struct TcpStreamWriteHalf {
    mss: usize,
    payload_sender: PollSender<BytesMut>,
}
#[cfg(feature = "global-ip-stack")]
impl TcpListener {
    pub async fn bind_all() -> io::Result<Self> {
        Self::bind0(IpStack::get()?, None).await
    }
    pub async fn bind<A: ToSocketAddr>(local_addr: A) -> io::Result<Self> {
        let ip_stack = IpStack::get()?;
        let local_addr = local_addr.to_addr()?;
        ip_stack.routes().check_bind_ip(local_addr.ip())?;
        Self::bind0(ip_stack, Some(local_addr)).await
    }
}
#[cfg(not(feature = "global-ip-stack"))]
impl TcpListener {
    pub async fn bind_all(ip_stack: IpStack) -> io::Result<Self> {
        Self::bind0(ip_stack, None).await
    }
    pub async fn bind<A: ToSocketAddr>(ip_stack: IpStack, local_addr: A) -> io::Result<Self> {
        let local_addr = local_addr.to_addr()?;
        ip_stack.routes().check_bind_ip(local_addr.ip())?;
        Self::bind0(ip_stack, Some(local_addr)).await
    }
}
impl TcpListener {
    async fn bind0(ip_stack: IpStack, mut local_addr: Option<SocketAddr>) -> io::Result<Self> {
        let (packet_sender, packet_receiver) = channel(ip_stack.config.tcp_syn_channel_size);
        let _bind_addr = if let Some(addr) = &mut local_addr {
            Some(ip_stack.bind(IpNextHeaderProtocols::Tcp, addr)?)
        } else {
            None
        };
        ip_stack.add_tcp_listener(local_addr, packet_sender)?;
        Ok(Self {
            _bind_addr,
            ip_stack,
            packet_receiver,
            local_addr,
            tcb_map: Default::default(),
        })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
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
                let acknowledgement = tcp_packet.get_acknowledgement();
                let sequence = tcp_packet.get_sequence();
                let local_addr = network_tuple.dst;
                let peer_addr = network_tuple.src;
                if tcp_packet.get_flags() & SYN == SYN {
                    // LISTEN -> SYN_RECEIVED
                    let tcp_config = self.ip_stack.config.tcp_config;
                    let mut tcb = Tcb::new_listen(local_addr, peer_addr, tcp_config);
                    if let Some(relay_packet) = tcb.try_syn_received(&tcp_packet) {
                        self.ip_stack.add_tcp_half_open(*network_tuple);
                        self.tcb_map.insert(*network_tuple, tcb);
                        self.ip_stack.send_packet(relay_packet).await?;
                        continue;
                    }
                } else if let Some(tcb) = self.tcb_map.get_mut(network_tuple) {
                    // SYN_RECEIVED -> ESTABLISHED
                    if tcb.try_syn_received_to_established(packet.buf) {
                        let tcb = self.tcb_map.remove(network_tuple).unwrap();
                        let stream = TcpStream::new(self.ip_stack.clone(), tcb);
                        self.ip_stack.remove_tcp_half_open(network_tuple);
                        return Ok((stream?, peer_addr));
                    }
                    if tcb.is_close() {
                        self.tcb_map.remove(network_tuple).unwrap();
                        self.ip_stack.remove_tcp_half_open(network_tuple);
                    }
                } else if tcp_packet.get_flags() & RST == RST {
                    continue;
                }
                let data = tcb::create_transport_packet_raw(
                    &local_addr,
                    &peer_addr,
                    acknowledgement,
                    sequence.wrapping_add(1),
                    0,
                    RST | ACK,
                    &[],
                );
                self.ip_stack.send_packet(data).await?;
            } else {
                return Err(Error::from(io::ErrorKind::UnexpectedEof));
            }
        }
    }
}
#[cfg(feature = "global-ip-stack")]
impl TcpStream {
    pub fn bind<A: ToSocketAddr>(local_addr: A) -> io::Result<Self> {
        let ip_stack = IpStack::get()?;
        let mut local_addr = local_addr.to_addr()?;
        ip_stack.routes().check_bind_ip(local_addr.ip())?;
        let bind_addr = ip_stack.bind(IpNextHeaderProtocols::Tcp, &mut local_addr)?;
        Ok(Self::new_uncheck(Some(bind_addr), Some(ip_stack), local_addr, None, None, None))
    }
    pub async fn connect<A: ToSocketAddr>(dest: A) -> io::Result<Self> {
        let dest = dest.to_addr()?;
        TcpStream::bind(default_addr(dest.is_ipv4()))?.connect_to(dest).await
    }
}
#[cfg(not(feature = "global-ip-stack"))]
impl TcpStream {
    pub fn bind<A: ToSocketAddr>(ip_stack: IpStack, local_addr: A) -> io::Result<Self> {
        let mut local_addr = local_addr.to_addr()?;
        ip_stack.routes().check_bind_ip(local_addr.ip())?;
        let bind_addr = ip_stack.bind(IpNextHeaderProtocols::Tcp, &mut local_addr)?;
        Ok(Self::new_uncheck(Some(bind_addr), Some(ip_stack), local_addr, None, None, None))
    }
    pub async fn connect<A: ToSocketAddr>(ip_stack: IpStack, dest: A) -> io::Result<Self> {
        let dest = dest.to_addr()?;
        TcpStream::bind(ip_stack, default_addr(dest.is_ipv4()))?.connect_to(dest).await
    }
}
impl TcpStream {
    pub async fn connect_to<A: ToSocketAddr>(self, dest: A) -> io::Result<Self> {
        let dest = dest.to_addr()?;
        validate_addr(dest)?;
        let Some(ip_stack) = self.ip_stack else {
            return Err(Error::new(io::ErrorKind::AlreadyExists, "transport endpoint is already connected"));
        };
        let mut src = self.local_addr;
        if src.is_ipv4() != dest.is_ipv4() {
            return Err(Error::new(io::ErrorKind::InvalidInput, "address error"));
        }
        if let Err(e) = check_ip(src.ip()) {
            if let Some(v) = ip_stack.routes().route(dest.ip()) {
                src.set_ip(v);
            } else {
                Err(e)?
            }
        }
        validate_addr(src)?;
        if src == dest {
            return Err(Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid self-connect: source and destination are identical ({src})"),
            ));
        }

        Self::connect0(self.bind_addr, ip_stack, src, dest).await
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        if let Some(v) = self.peer_addr {
            Ok(v)
        } else {
            Err(Error::from(io::ErrorKind::NotConnected))
        }
    }
    pub fn split(self) -> io::Result<(TcpStreamWriteHalf, TcpStreamReadHalf)> {
        match (self.write, self.read) {
            (Some(write), Some(read)) => Ok((write, read)),
            _ => Err(Error::from(io::ErrorKind::NotConnected)),
        }
    }
}

impl TcpStream {
    fn as_mut_read(&mut self) -> io::Result<&mut TcpStreamReadHalf> {
        if let Some(v) = self.read.as_mut() {
            Ok(v)
        } else {
            Err(Error::from(io::ErrorKind::NotConnected))
        }
    }
    fn as_mut_write(&mut self) -> io::Result<&mut TcpStreamWriteHalf> {
        if let Some(v) = self.write.as_mut() {
            Ok(v)
        } else {
            Err(Error::from(io::ErrorKind::NotConnected))
        }
    }
    pub(crate) async fn connect0(
        bind_addr: Option<BindAddr>,
        ip_stack: IpStack,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> io::Result<Self> {
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
        let mut stream_task = TcpStreamTask::new(bind_addr, tcb, ip_stack, payload_sender, payload_receiver_w, packet_receiver);
        stream_task.connect().await?;
        let read_notify = stream_task.read_notify();
        let mss = stream_task.mss() as usize;
        tokio::spawn(async move {
            if let Err(e) = stream_task.run().await {
                log::warn!("stream_task run {local_addr}->{peer_addr}: {e:?}")
            }
        });
        let read = TcpStreamReadHalf {
            read_notify,
            last_buf: None,
            payload_receiver,
        };
        let write = TcpStreamWriteHalf {
            mss,
            payload_sender: PollSender::new(payload_sender_w),
        };
        let stream = Self::new_uncheck(None, None, local_addr, Some(peer_addr), Some(read), Some(write));
        Ok(stream)
    }
    fn new_uncheck(
        bind_addr: Option<BindAddr>,
        ip_stack: Option<IpStack>,
        local_addr: SocketAddr,
        peer_addr: Option<SocketAddr>,
        read: Option<TcpStreamReadHalf>,
        write: Option<TcpStreamWriteHalf>,
    ) -> Self {
        Self {
            bind_addr,
            ip_stack,
            local_addr,
            peer_addr,
            read,
            write,
        }
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
        let stream_task = TcpStreamTask::new(None, tcb, ip_stack, payload_sender, payload_receiver_w, packet_receiver);
        let read_notify = stream_task.read_notify();
        let read = TcpStreamReadHalf {
            read_notify,
            last_buf: None,
            payload_receiver,
        };
        let write = TcpStreamWriteHalf {
            mss,
            payload_sender: PollSender::new(payload_sender_w),
        };
        let stream = Self::new_uncheck(None, None, local_addr, Some(peer_addr), Some(read), Some(write));
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
        Pin::new(self.as_mut_read()?).poll_read(cx, buf)
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
                if self.try_read0(buf) {
                    self.read_notify.notify();
                }
            }
            return Poll::Ready(Ok(()));
        }
        let poll = self.payload_receiver.poll_recv(cx);
        match poll {
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(mut p)) => {
                if p.is_empty() {
                    self.payload_receiver.close();
                    return Poll::Ready(Ok(()));
                }
                let len = buf.remaining().min(p.len());
                buf.put_slice(&p[..len]);
                p.advance(len);
                if p.is_empty() {
                    self.try_read0(buf);
                } else {
                    self.last_buf.replace(p);
                }
                self.read_notify.notify();
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for TcpStreamReadHalf {
    fn drop(&mut self) {
        self.payload_receiver.close();
        self.read_notify.close();
    }
}
impl TcpStreamReadHalf {
    fn try_read0(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        let mut rs = false;
        while buf.remaining() > 0 {
            let Ok(mut p) = self.payload_receiver.try_recv() else {
                break;
            };
            rs = true;
            if p.is_empty() {
                self.payload_receiver.close();
                break;
            }
            let len = buf.remaining().min(p.len());
            buf.put_slice(&p[..len]);
            p.advance(len);
            if !p.is_empty() {
                self.last_buf.replace(p);
            }
        }
        rs
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        Pin::new(self.as_mut_write()?).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(self.as_mut_write()?).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(self.as_mut_write()?).poll_shutdown(cx)
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

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.payload_sender.close();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.ip_stack.remove_tcp_listener(&self.local_addr)
    }
}
