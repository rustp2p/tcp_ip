use std::io;
use std::io::Error;
use std::ops::Add;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use pnet_packet::ip::IpNextHeaderProtocols;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::ip_stack::{BindAddr, IpStack, NetworkTuple, TransportPacket};
use crate::tcp::tcb::Tcb;

#[derive(Debug)]
pub struct TcpStreamTask {
    _bind_addr: Option<BindAddr>,
    quick_end: bool,
    tcb: Tcb,
    ip_stack: IpStack,
    application_layer_receiver: Receiver<BytesMut>,
    last_buffer: Option<BytesMut>,
    packet_receiver: Receiver<TransportPacket>,
    application_layer_sender: Option<Sender<BytesMut>>,
    write_half_closed: bool,
    retransmission: bool,
    read_notify: ReadNotify,
}

#[derive(Clone, Default, Debug)]
pub struct ReadNotify {
    readable: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl ReadNotify {
    pub fn notify(&self) {
        if self.readable.load(Ordering::Acquire) {
            self.notify.notify_one();
        }
    }
    pub fn close(&self) {
        self.notify.notify_one();
    }
    async fn notified(&self) {
        self.notify.notified().await
    }
    fn set_state(&self, readable: bool) {
        self.readable.store(readable, Ordering::Release);
    }
}

impl Drop for TcpStreamTask {
    fn drop(&mut self) {
        let peer_addr = self.tcb.peer_addr();
        let local_addr = self.tcb.local_addr();
        let network_tuple = NetworkTuple::new(peer_addr, local_addr, IpNextHeaderProtocols::Tcp);
        self.ip_stack.remove_tcp_socket(&network_tuple);
    }
}

impl TcpStreamTask {
    pub fn new(
        _bind_addr: Option<BindAddr>,
        tcb: Tcb,
        ip_stack: IpStack,
        application_layer_sender: Sender<BytesMut>,
        application_layer_receiver: Receiver<BytesMut>,
        packet_receiver: Receiver<TransportPacket>,
    ) -> Self {
        Self {
            _bind_addr,
            quick_end: ip_stack.config.tcp_config.quick_end,
            tcb,
            ip_stack,
            application_layer_receiver,
            last_buffer: None,
            packet_receiver,
            application_layer_sender: Some(application_layer_sender),
            write_half_closed: false,
            retransmission: false,
            read_notify: Default::default(),
        }
    }
    pub fn read_notify(&self) -> ReadNotify {
        self.read_notify.clone()
    }
}

impl TcpStreamTask {
    pub async fn run(&mut self) -> io::Result<()> {
        let result = self.run0().await;
        self.push_application_layer();
        result
    }
    pub async fn run0(&mut self) -> io::Result<()> {
        loop {
            if self.tcb.is_close() {
                return Ok(());
            }
            if self.quick_end && self.read_half_closed() && self.write_half_closed {
                return Ok(());
            }
            if !self.write_half_closed && !self.retransmission {
                self.flush().await?;
            }
            let data = self.recv_data().await;

            match data {
                TaskRecvData::In(mut buf) => {
                    let mut count = 0;
                    loop {
                        if let Some(reply_packet) = self.tcb.push_packet(buf) {
                            self.send_packet(reply_packet).await?;
                        }

                        if self.tcb.is_close() {
                            return Ok(());
                        }
                        if !self.tcb.readable_state() {
                            break;
                        }
                        count += 1;
                        if count >= 10 {
                            break;
                        }
                        if let Some(v) = self.try_recv_in() {
                            buf = v
                        } else {
                            break;
                        }
                    }
                    self.push_application_layer();
                    // if self.tcb.readable_state() && self.application_layer_sender.is_some() && self.tcb.readable() && self.tcb.recv_busy() {
                    //     // The window is too small and requires blocking to wait; otherwise, it will lead to severe packet loss
                    //     self.read_notify.notified().await;
                    //     self.push_application_layer();
                    // }
                }
                TaskRecvData::Out(buf) => {
                    self.write(buf).await?;
                }
                TaskRecvData::InClose => return Err(Error::other("NetworkDown")),
                TaskRecvData::OutClose => {
                    assert!(self.last_buffer.is_none());
                    self.write_half_closed = true;
                    let packet = self.tcb.fin_packet();
                    self.send_packet(packet).await?;
                    self.tcb.sent_fin();
                }
                TaskRecvData::Timeout => {
                    self.tcb.timeout();
                    if self.tcb.is_close() {
                        return Ok(());
                    }
                    if self.tcb.cannot_write() {
                        let packet = self.tcb.fin_packet();
                        self.send_packet(packet).await?;
                    }
                    if self.read_half_closed() && self.write_half_closed {
                        return Ok(());
                    }
                }
                TaskRecvData::ReadNotify => {
                    self.push_application_layer();
                    self.try_send_ack().await?;
                }
            }
            self.retransmission = self.try_retransmission().await?;
            self.try_send_ack().await?;
            self.tcb.perform_post_ack_action();
            if !self.read_half_closed() && self.tcb.cannot_read() {
                self.close_read();
            }
        }
    }
    async fn send_packet(&mut self, transport_packet: TransportPacket) -> io::Result<()> {
        self.ip_stack.send_packet(transport_packet).await?;
        self.tcb.perform_post_ack_action();
        Ok(())
    }
    fn read_half_closed(&self) -> bool {
        if let Some(v) = self.application_layer_sender.as_ref() {
            v.is_closed()
        } else {
            true
        }
    }
    pub fn mss(&self) -> u16 {
        self.tcb.mss()
    }
    fn only_recv_in(&self) -> bool {
        self.retransmission || self.last_buffer.is_some() || self.write_half_closed || self.tcb.limit()
    }
    fn push_application_layer(&mut self) {
        if let Some(sender) = self.application_layer_sender.as_ref() {
            let mut read_half_closed = false;
            while self.tcb.readable() {
                match sender.try_reserve() {
                    Ok(sender) => {
                        if let Some(buffer) = self.tcb.read() {
                            sender.send(buffer);
                        }
                    }
                    Err(e) => match e {
                        TrySendError::Full(_) => break,
                        TrySendError::Closed(_) => {
                            read_half_closed = true;
                            break;
                        }
                    },
                }
                self.read_notify.set_state(self.tcb.readable());
            }
            if self.tcb.cannot_read() || read_half_closed {
                self.close_read();
            }
        } else {
            self.tcb.read_none();
        }
    }
    fn close_read(&mut self) {
        if let Some(sender) = self.application_layer_sender.take() {
            _ = sender.try_send(BytesMut::new());
        }
    }
    async fn write_slice0(tcb: &mut Tcb, ip_stack: &IpStack, mut buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();
        while !buf.is_empty() {
            if let Some((packet, len)) = tcb.write(buf) {
                if len == 0 {
                    break;
                }
                ip_stack.send_packet(packet).await?;
                tcb.perform_post_ack_action();
                buf = &buf[len..];
            } else {
                break;
            }
        }
        Ok(len - buf.len())
    }
    async fn write_slice(&mut self, buf: &[u8]) -> io::Result<usize> {
        Self::write_slice0(&mut self.tcb, &self.ip_stack, buf).await
    }
    async fn write(&mut self, mut buf: BytesMut) -> io::Result<usize> {
        let len = self.write_slice(&buf).await?;
        if len != buf.len() {
            // Buffer is full
            buf.advance(len);
            self.last_buffer.replace(buf);
        }
        Ok(len)
    }
    async fn flush(&mut self) -> io::Result<()> {
        if let Some(buf) = self.last_buffer.as_mut() {
            let len = Self::write_slice0(&mut self.tcb, &self.ip_stack, buf).await?;
            if buf.len() == len {
                self.last_buffer.take();
            } else {
                buf.advance(len);
            }
        }
        Ok(())
    }

    async fn try_retransmission(&mut self) -> io::Result<bool> {
        if self.write_half_closed {
            return Ok(false);
        }
        if let Some(v) = self.tcb.retransmission() {
            self.send_packet(v).await?;
            return Ok(true);
        }
        if self.tcb.no_inflight_packet() {
            return Ok(false);
        }
        if self.tcb.need_retransmission() {
            if let Some(v) = self.tcb.retransmission() {
                self.send_packet(v).await?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    async fn try_send_ack(&mut self) -> io::Result<()> {
        if self.tcb.need_ack() {
            let packet = self.tcb.ack_packet();
            self.ip_stack.send_packet(packet).await?;
        }
        Ok(())
    }

    async fn recv_data(&mut self) -> TaskRecvData {
        let deadline = if let Some(v) = self.tcb.time_wait() {
            Some(v.into())
        } else {
            self.tcb.write_timeout().map(|v| v.into())
        };

        if let Some(deadline) = deadline {
            if self.only_recv_in() {
                self.recv_in_timeout_at(deadline).await
            } else {
                self.recv_timeout_at(deadline).await
            }
        } else if self.write_half_closed {
            let timeout_at = Instant::now().add(self.ip_stack.config.tcp_config.time_wait_timeout);
            self.recv_in_timeout_at(timeout_at).await
        } else {
            self.recv().await
        }
    }
    async fn recv(&mut self) -> TaskRecvData {
        tokio::select! {
            rs=self.packet_receiver.recv()=>{
                rs.map(|v| TaskRecvData::In(v.buf)).unwrap_or(TaskRecvData::InClose)
            }
            rs=self.application_layer_receiver.recv()=>{
                rs.map(TaskRecvData::Out).unwrap_or(TaskRecvData::OutClose)
            }
            _=self.read_notify.notified()=>{
                TaskRecvData::ReadNotify
            }
        }
    }
    async fn recv_timeout_at(&mut self, deadline: Instant) -> TaskRecvData {
        tokio::select! {
            rs=self.packet_receiver.recv()=>{
                rs.map(|v| TaskRecvData::In(v.buf)).unwrap_or(TaskRecvData::InClose)
            }
            rs=self.application_layer_receiver.recv()=>{
                rs.map(TaskRecvData::Out).unwrap_or(TaskRecvData::OutClose)
            }
            _=tokio::time::sleep_until(deadline)=>{
                TaskRecvData::Timeout
            }
            _=self.read_notify.notified()=>{
                TaskRecvData::ReadNotify
            }
        }
    }

    async fn recv_in_timeout_at(&mut self, deadline: Instant) -> TaskRecvData {
        tokio::select! {
            rs=self.packet_receiver.recv()=>{
                rs.map(|v| TaskRecvData::In(v.buf)).unwrap_or(TaskRecvData::InClose)
            }
            _=tokio::time::sleep_until(deadline)=>{
                TaskRecvData::Timeout
            }
            _=self.read_notify.notified()=>{
                TaskRecvData::ReadNotify
            }
        }
    }
    async fn recv_in_timeout(&mut self, duration: Duration) -> TaskRecvData {
        self.recv_in_timeout_at(Instant::now().add(duration)).await
    }

    fn try_recv_in(&mut self) -> Option<BytesMut> {
        self.packet_receiver.try_recv().map(|v| v.buf).ok()
    }
}

impl TcpStreamTask {
    pub async fn connect(&mut self) -> io::Result<()> {
        let mut count = 0;
        let mut time = 50;
        while let Some(packet) = self.tcb.try_syn_sent() {
            count += 1;
            if count > 50 {
                break;
            }
            self.send_packet(packet).await?;
            time *= 2;
            return match self.recv_in_timeout(Duration::from_millis(time.min(3000))).await {
                TaskRecvData::In(buf) => {
                    if let Some(relay) = self.tcb.try_syn_sent_to_established(buf) {
                        self.send_packet(relay).await?;
                        Ok(())
                    } else {
                        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                    }
                }
                TaskRecvData::InClose => Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
                TaskRecvData::Timeout => continue,
                _ => {
                    unreachable!()
                }
            };
        }
        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
    }
}

enum TaskRecvData {
    In(BytesMut),
    Out(BytesMut),
    ReadNotify,
    InClose,
    OutClose,
    Timeout,
}
