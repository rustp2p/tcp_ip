use crate::ip_stack::{IpStack, NetworkTuple, TransportPacket, UNSPECIFIED_ADDR};
use crate::tcp::tcb::{Tcb, TcbRead, TcbWrite};
use bytes::{Buf, BufMut, BytesMut};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::TcpFlags::{ACK, PSH, RST, SYN};
use rand::RngCore;
use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use pnet_packet::tcp::TcpPacket;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::futures::Notified;
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Notify;
use tokio_util::sync::{PollSendError, PollSender};

mod tcb;

pub struct TcpListener {
    ip_stack: IpStack,
    packet_receiver: Receiver<TransportPacket>,
    local_addr: SocketAddr,
    tcb_map: HashMap<NetworkTuple, Tcb>,
}

pub struct TcpStream {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    last_buf: Option<BytesMut>,
    payload_receiver: Receiver<BytesMut>,
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
                if let Some(v) = self
                    .ip_stack
                    .inner
                    .tcp_stream_map
                    .get(network_tuple)
                    .as_deref()
                    .cloned()
                {
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
                    let tcb = Tcb::new_syn_received(
                        local_addr,
                        peer_addr,
                        tcp_packet.get_sequence(),
                        tcp_packet.get_window(),
                        self.ip_stack.config.mtu,
                    );
                    let data = tcb.create_transport_packet(SYN | ACK, &[]);
                    self.ip_stack.send_packet(data).await?;
                    self.tcb_map.insert(*network_tuple, tcb);
                } else if let Some(tcb) = self.tcb_map.get_mut(network_tuple) {
                    // SYN_RECEIVED -> ESTABLISHED
                    if tcb.try_established(packet.buf) {
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
        todo!()
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
}

impl TcpStream {
    pub(crate) fn new(ip_stack: IpStack, tcb: Tcb) -> io::Result<Self> {
        let tcp_context = Arc::new(TcpContext::from(&tcb));
        let peer_addr = tcb.peer_addr();
        let local_addr = tcb.local_addr();
        let (tcb_write, tcb_read) = tcb.split();
        let (payload_sender_w, payload_receiver_w) = channel(ip_stack.config.tcp_channel_size);
        let (payload_sender, payload_receiver) = channel(ip_stack.config.tcp_channel_size);
        let (packet_sender, packet_receiver) = channel(ip_stack.config.tcp_channel_size);
        let network_tuple = NetworkTuple::new(peer_addr, local_addr, IpNextHeaderProtocols::Tcp);
        ip_stack.add_tcp_socket(network_tuple, packet_sender)?;

        let mut stream_read = TcpStreamRead {
            tcb_read,
            tcp_context: tcp_context.clone(),
            packet_receiver,
            payload_sender,
        };
        let mut stream_write =
            TcpStreamWrite::new(tcp_context, tcb_write, ip_stack, payload_receiver_w);
        tokio::spawn(async move {
            if let Err(e) = stream_write.loop_send().await {
                log::warn!("{:?}: {e:?}", network_tuple)
            }
        });
        tokio::spawn(async move {
            stream_read.loop_recv().await;
        });

        Ok(Self {
            local_addr,
            peer_addr,
            last_buf: None,
            payload_receiver,
            payload_sender: PollSender::new(payload_sender_w),
        })
    }
}

struct TcpStreamRead {
    tcb_read: TcbRead,
    tcp_context: Arc<TcpContext>,
    packet_receiver: Receiver<TransportPacket>,
    payload_sender: Sender<BytesMut>,
}

impl TcpStreamRead {
    async fn loop_recv(&mut self) {
        loop {
            let Some(packet) = self.packet_receiver.recv().await else {
                break;
            };
            self.update_state();

            self.tcb_read.push_packet(packet.buf);
            let mut buffer = BytesMut::zeroed(2048);
            let len = self.tcb_read.read(&mut buffer);
            buffer.truncate(len);
            if !buffer.is_empty() {
                match self.payload_sender.send(buffer).await {
                    Ok(_) => {}
                    Err(e) => {
                        // todo shutdown
                        log::error!("close");
                        break;
                    }
                }
            }
            let snd_ack_distance = self.update_context();
            if snd_ack_distance > 0 {
                // Notify sending ack
                self.tcp_context.notify_write.notify_one();
            }
            // todo 减少接收窗口
        }
    }
    fn update_state(&mut self) {
        let snd_seq = self.tcp_context.snd_seq();
        self.tcb_read.update_snd_seq(snd_seq);
    }
    fn update_context(&self) -> u32 {
        let snd_ack = self.tcb_read.snd_ack();
        let snd_wnd = self.tcb_read.snd_wnd();
        let rcv_wnd = self.tcb_read.rcv_wnd();
        let last_ack = self.tcb_read.last_ack();
        let duplicate_ack_count = self.tcb_read.duplicate_ack_count();
        let snd_ack_distance = snd_ack.wrapping_sub(self.tcp_context.snd_ack());
        self.tcp_context.set_snd_ack(snd_ack);
        self.tcp_context.set_snd_wnd(snd_wnd);
        self.tcp_context.set_rcv_wnd(rcv_wnd);
        self.tcp_context.set_last_ack(last_ack);
        self.tcp_context
            .set_duplicate_ack_count(duplicate_ack_count);
        snd_ack_distance
    }
}

struct TcpStreamWrite {
    tcp_context: Arc<TcpContext>,
    tcb_write: TcbWrite,
    ip_stack: IpStack,
    payload_receiver: Receiver<BytesMut>,
    last_buffer: Option<BytesMut>,
    timeout_flag: bool,
}

impl TcpStreamWrite {
    fn new(
        tcp_context: Arc<TcpContext>,
        tcb_write: TcbWrite,
        ip_stack: IpStack,
        payload_receiver: Receiver<BytesMut>,
    ) -> Self {
        Self {
            tcp_context,
            tcb_write,
            ip_stack,
            payload_receiver,
            last_buffer: None,
            timeout_flag: false,
        }
    }
}

impl TcpStreamWrite {
    async fn loop_send(&mut self) -> io::Result<()> {
        let timeout = self.ip_stack.config.retransmission_timeout;
        let deadline = tokio::time::Instant::now() + timeout;
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        let tcp_context = self.tcp_context.clone();
        let notify_write = tcp_context.notify_write.clone();
        let notified = notify_write.notified();
        tokio::pin!(notified);
        loop {
            let snd_ack_distance = self.update_state();
            let retransmission = self.try_retransmission().await?;
            if !retransmission && !self.try_write().await? && snd_ack_distance > 0 {
                self.send_ack().await?;
            }

            if retransmission || self.last_buffer.is_some() {
                let deadline = tokio::time::Instant::now() + timeout;
                sleep.as_mut().reset(deadline);
                tokio::select! {
                    _=&mut sleep =>{
                        self.timeout();
                    }
                    _=&mut notified=>{
                        notified.set(notify_write.notified());
                    }
                }
            } else if self.tcb_write.no_inflight_packet() {
                tokio::select! {
                    rs=self.payload_receiver.recv()=>{
                        if let Some(buf) = rs{
                            self.write(buf).await?;
                        }else{
                            // write shutdown
                            break;
                        }
                    }
                    _=&mut notified=>{
                        notified.set(notify_write.notified());
                    }
                }
            } else {
                let deadline = tokio::time::Instant::now() + timeout;
                sleep.as_mut().reset(deadline);
                tokio::select! {
                    _=&mut sleep =>{
                        self.timeout();
                    }
                    rs=self.payload_receiver.recv()=>{
                        if let Some(buf) = rs{
                            self.write(buf).await?;
                        }else{
                            // write shutdown
                            break;
                        }
                    }
                    _=&mut notified=>{
                        notified.set(notify_write.notified());
                    }
                }
            }
        }
        Ok(())
    }
    async fn try_write(&mut self) -> io::Result<bool> {
        if let Some(buf) = self.last_buffer.as_mut() {
            if let Some((packet, len)) = self.tcb_write.write(&buf) {
                self.ip_stack.send_packet(packet).await?;
                if buf.len() == len {
                    self.last_buffer.take();
                } else {
                    buf.advance(len);
                }
                self.update_seq();
            }
            return Ok(true);
        }
        if self.tcb_write.no_inflight_packet() {
            if let Ok(packet) = self.payload_receiver.try_recv() {
                self.write(packet).await?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    async fn send_ack(&self) -> io::Result<()> {
        let packet = self.tcb_write.create_transport_packet(PSH | ACK, &[]);
        self.ip_stack.send_packet(packet).await
    }
    async fn write(&mut self, mut buf: BytesMut) -> io::Result<usize> {
        if let Some((packet, len)) = self.tcb_write.write(&buf) {
            self.ip_stack.send_packet(packet).await?;
            if len != buf.len() {
                // Buffer is full
                buf.advance(len);
                self.last_buffer.replace(buf);
            }
            self.update_seq();
            Ok(len)
        } else {
            Ok(0)
        }
    }
    fn update_state(&mut self) -> u32 {
        let snd_ack = self.tcp_context.snd_ack();
        let last_ack = self.tcp_context.last_ack();
        let rcv_wnd = self.tcp_context.rcv_wnd();
        let snd_ack_distance = snd_ack.wrapping_sub(self.tcb_write.snd_ack());
        self.tcb_write.update_last_ack(last_ack);
        self.tcb_write.update_snd_ack(snd_ack);
        self.tcb_write.update_rcv_wnd(rcv_wnd);
        snd_ack_distance
    }
    fn update_seq(&self) {
        let snd_seq = self.tcb_write.snd_seq();
        self.tcp_context.set_snd_seq(snd_seq);
    }
    fn timeout(&mut self) {
        // Mark as timeout, trigger retransmission
        self.timeout_flag = true;
    }
    fn reset_timeout(&mut self) {
        self.timeout_flag = false;
    }
    fn need_retransmission(&mut self) -> bool {
        let timeout_flag = self.timeout_flag;
        self.reset_timeout();
        timeout_flag || self.tcp_context.duplicate_ack_count() >= 3
    }
    async fn try_retransmission(&mut self) -> io::Result<bool> {
        if let Some(v) = self.tcb_write.retransmission() {
            self.ip_stack.send_packet(v).await?;
            return Ok(true);
        }
        if self.need_retransmission() {
            self.tcb_write.back_n();
            if let Some(v) = self.tcb_write.retransmission() {
                self.ip_stack.send_packet(v).await?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

struct TcpContext {
    notify_write: Arc<Notify>,
    snd_seq: AtomicU32,
    snd_ack: AtomicU32,
    last_ack: AtomicU32,
    duplicate_ack_count: AtomicU32,
    snd_wnd: AtomicU16,
    rcv_wnd: AtomicU16,
}

impl TcpContext {
    fn from(tcb: &Tcb) -> Self {
        Self::new(
            tcb.snd_seq(),
            tcb.snd_ack(),
            tcb.last_ack(),
            tcb.snd_wnd(),
            tcb.rcv_wnd(),
        )
    }
    fn new(snd_seq: u32, snd_ack: u32, last_ack: u32, snd_wnd: u16, rcv_wnd: u16) -> Self {
        Self {
            notify_write: Arc::new(Default::default()),
            snd_seq: AtomicU32::new(snd_seq),
            snd_ack: AtomicU32::new(snd_ack),
            last_ack: AtomicU32::new(last_ack),
            duplicate_ack_count: Default::default(),
            snd_wnd: AtomicU16::new(snd_wnd),
            rcv_wnd: AtomicU16::new(rcv_wnd),
        }
    }
    fn snd_seq(&self) -> u32 {
        self.snd_seq.load(Ordering::Acquire)
    }
    fn snd_ack(&self) -> u32 {
        self.snd_ack.load(Ordering::Acquire)
    }
    fn last_ack(&self) -> u32 {
        self.last_ack.load(Ordering::Acquire)
    }
    fn duplicate_ack_count(&self) -> u32 {
        self.duplicate_ack_count.load(Ordering::Acquire)
    }
    fn snd_wnd(&self) -> u16 {
        self.snd_wnd.load(Ordering::Acquire)
    }
    fn rcv_wnd(&self) -> u16 {
        self.rcv_wnd.load(Ordering::Acquire)
    }
    fn set_snd_seq(&self, value: u32) {
        self.snd_seq.store(value, Ordering::Release);
    }

    fn set_snd_ack(&self, value: u32) {
        self.snd_ack.store(value, Ordering::Release);
    }

    fn set_last_ack(&self, value: u32) {
        self.last_ack.store(value, Ordering::Release);
    }
    fn set_duplicate_ack_count(&self, value: u32) {
        self.duplicate_ack_count.store(value, Ordering::Release);
    }

    fn set_snd_wnd(&self, value: u16) {
        self.snd_wnd.store(value, Ordering::Release);
    }

    fn set_rcv_wnd(&self, value: u16) {
        self.rcv_wnd.store(value, Ordering::Release);
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
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
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        if buf.is_empty() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
        }
        match self.payload_sender.poll_reserve(cx) {
            Poll::Ready(Ok(_)) => {
                _ = self.payload_sender.send_item(buf.into());
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        todo!()
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.ip_stack.remove_tcp_listener(&self.local_addr)
    }
}
