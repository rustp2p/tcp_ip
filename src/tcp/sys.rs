use std::io;
use std::io::Error;
use std::pin::Pin;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use pnet_packet::ip::IpNextHeaderProtocols;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::Instant;

use crate::ip_stack::{IpStack, NetworkTuple, TransportPacket};
use crate::tcp::tcb::Tcb;

#[derive(Debug)]
pub struct TcpStreamTask {
    tcb: Tcb,
    ip_stack: IpStack,
    application_layer_receiver: Receiver<BytesMut>,
    last_buffer: Option<BytesMut>,
    packet_receiver: Receiver<TransportPacket>,
    application_layer_sender: Sender<BytesMut>,
    timeout: Duration,
    read_half_closed: bool,
    write_half_closed: bool,
    retransmission: bool,
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
        tcb: Tcb,
        ip_stack: IpStack,
        application_layer_sender: Sender<BytesMut>,
        application_layer_receiver: Receiver<BytesMut>,
        packet_receiver: Receiver<TransportPacket>,
    ) -> Self {
        let timeout = ip_stack.config.tcp_config.retransmission_timeout;
        Self {
            tcb,
            ip_stack,
            application_layer_receiver,
            last_buffer: None,
            packet_receiver,
            application_layer_sender,
            timeout,
            read_half_closed: false,
            write_half_closed: false,
            retransmission: false,
        }
    }
}

impl TcpStreamTask {
    pub async fn run(&mut self) -> io::Result<()> {
        let result = self.run0().await;
        self.push_application_layer().await;
        result
    }
    pub async fn run0(&mut self) -> io::Result<()> {
        loop {
            if self.tcb.is_close() {
                return Ok(());
            }

            let deadline = if let Some(v) = self.tcb.time_wait() {
                Some(v.into())
            } else {
                self.tcb.write_timeout().map(|v| v.into())
            };

            let data = if let Some(deadline) = deadline {
                if self.only_recv_in() {
                    self.recv_in_timeout_at(deadline).await
                } else {
                    self.recv_timeout_at(deadline).await
                }
            } else {
                if self.only_recv_in() {
                    self.recv_in().await
                } else {
                    self.recv().await
                }
            };
            if !self.write_half_closed && !self.retransmission {
                self.flush().await?;
            }
            match data {
                TaskRecvData::In(buf) => {
                    if let Some(reply_packet) = self.tcb.push_packet(buf) {
                        self.ip_stack.send_packet(reply_packet).await?;
                    }
                    self.push_application_layer().await;
                }
                TaskRecvData::Out(buf) => {
                    self.write(buf).await?;
                }
                TaskRecvData::InClose => return Err(Error::new(io::ErrorKind::Other, "NetworkDown")),
                TaskRecvData::OutClose => {
                    assert!(self.last_buffer.is_none());
                    self.write_half_closed = true;
                    let packet = self.tcb.fin_packet();
                    self.ip_stack.send_packet(packet).await?;
                    self.tcb.sent_fin();
                }
                TaskRecvData::Timeout => {
                    self.tcb.timeout();
                    if self.tcb.is_close() {
                        return Ok(());
                    }
                    if self.tcb.cannot_write() {
                        let packet = self.tcb.fin_packet();
                        self.ip_stack.send_packet(packet).await?;
                    }
                }
            }
            if self.try_retransmission().await? {
                self.retransmission = true;
            } else {
                self.retransmission = false;
                self.try_send_ack().await?;
            }
            if !self.read_half_closed && self.tcb.cannot_read() {
                self.close_read().await;
            }
        }
    }
    pub fn mss(&self) -> u16 {
        self.tcb.mss()
    }
    fn only_recv_in(&self) -> bool {
        self.retransmission || self.last_buffer.is_some() || self.write_half_closed || self.tcb.limit()
    }
    async fn push_application_layer(&mut self) {
        if self.read_half_closed {
            self.tcb.read_none();
        } else {
            let len = self.tcb.readable();
            if len > 0 {
                let mut buffer = BytesMut::zeroed(len);
                let len = self.tcb.read(&mut buffer);
                buffer.truncate(len);
                if !buffer.is_empty() {
                    match self.application_layer_sender.send(buffer).await {
                        Ok(_) => {}
                        Err(_e) => {
                            // Ignore the closure of reading
                            self.read_half_closed = true;
                        }
                    }
                }
            }
            if self.tcb.cannot_read() {
                self.close_read().await;
            }
        }
    }
    async fn close_read(&mut self) {
        _ = self.application_layer_sender.send(BytesMut::new()).await;
        self.read_half_closed = true;
    }
    async fn write_slice0(tcb: &mut Tcb, ip_stack: &IpStack, mut buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();
        while !buf.is_empty() {
            if let Some((packet, len)) = tcb.write(&buf) {
                if len == 0 {
                    break;
                }
                ip_stack.send_packet(packet).await?;
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
            self.ip_stack.send_packet(v).await?;
            return Ok(true);
        }
        if self.tcb.no_inflight_packet() {
            return Ok(false);
        }
        if self.tcb.need_retransmission() {
            if let Some(v) = self.tcb.retransmission() {
                self.ip_stack.send_packet(v).await?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    async fn try_send_ack(&mut self) -> io::Result<()> {
        if self.tcb.need_ack() {
            self.tcb.set_ack();
            let packet = self.tcb.ack_packet();
            self.ip_stack.send_packet(packet).await?;
        }
        Ok(())
    }

    async fn recv_timeout_at(&mut self, deadline: Instant) -> TaskRecvData {
        tokio::select! {
            rs=self.packet_receiver.recv()=>{
                rs.map(|v| TaskRecvData::In(v.buf)).unwrap_or(TaskRecvData::InClose)
            }
            rs=self.application_layer_receiver.recv()=>{
                rs.map(|v| TaskRecvData::Out(v)).unwrap_or(TaskRecvData::OutClose)
            }
            _=tokio::time::sleep_until(deadline)=>{
                TaskRecvData::Timeout
            }
        }
    }
    async fn recv(&mut self) -> TaskRecvData {
        tokio::select! {
            rs=self.packet_receiver.recv()=>{
                rs.map(|v| TaskRecvData::In(v.buf)).unwrap_or(TaskRecvData::InClose)
            }
            rs=self.application_layer_receiver.recv()=>{
                rs.map(|v| TaskRecvData::Out(v)).unwrap_or(TaskRecvData::OutClose)
            }
        }
    }
    fn try_recv_in(&mut self) -> Option<TaskRecvData> {
        match self.packet_receiver.try_recv() {
            Ok(rs) => Some(TaskRecvData::In(rs.buf)),
            Err(e) => match e {
                TryRecvError::Empty => None,
                TryRecvError::Disconnected => Some(TaskRecvData::InClose),
            },
        }
    }
    async fn recv_in_timeout_at(&mut self, deadline: Instant) -> TaskRecvData {
        tokio::time::timeout_at(deadline, self.recv_in())
            .await
            .unwrap_or_else(|_| TaskRecvData::Timeout)
    }
    async fn recv_in_timeout(&mut self, duration: Duration) -> TaskRecvData {
        tokio::time::timeout(duration, self.recv_in())
            .await
            .unwrap_or_else(|_| TaskRecvData::Timeout)
    }
    async fn recv_in(&mut self) -> TaskRecvData {
        let rs = self.packet_receiver.recv().await;
        rs.map(|v| TaskRecvData::In(v.buf)).unwrap_or(TaskRecvData::InClose)
    }
    async fn recv_out(&mut self) -> TaskRecvData {
        let rs = self.application_layer_receiver.recv().await;
        rs.map(|v| TaskRecvData::Out(v)).unwrap_or(TaskRecvData::OutClose)
    }
}

impl TcpStreamTask {
    pub async fn connect(&mut self) -> io::Result<()> {
        let mut count = 0;
        while let Some(packet) = self.tcb.try_syn_sent() {
            count += 1;
            if count > 50 {
                break;
            }
            self.ip_stack.send_packet(packet).await?;
            return match self.recv_in_timeout(Duration::from_millis(5000)).await {
                TaskRecvData::In(buf) => {
                    if let Some(relay) = self.tcb.try_syn_sent_to_established(buf) {
                        self.ip_stack.send_packet(relay).await?;
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
    InClose,
    OutClose,
    Timeout,
}
