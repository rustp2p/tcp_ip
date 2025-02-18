use std::cmp::Ordering;
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::{Add, Sub};
use std::time::{Duration, Instant};

use bytes::{Buf, BufMut, BytesMut};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::TcpFlags::{ACK, FIN, PSH, RST, SYN};
use pnet_packet::tcp::{TcpOptionNumber, TcpOptionNumbers, TcpPacket};
use pnet_packet::Packet;
use rand::RngCore;

use crate::buffer::FixedBuffer;
use crate::ip_stack::{NetworkTuple, TransportPacket};
use crate::tcp::tcp_queue::{TcpOfoQueue, TcpReceiveQueue};

const IP_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
pub const IP_TCP_HEADER_LEN: usize = IP_HEADER_LEN + TCP_HEADER_LEN;
const MAX_DIFF: u32 = u32::MAX / 2;
const MSS_MIN: u16 = 536;

/// Enum representing the various states of a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, num_enum::IntoPrimitive, num_enum::TryFromPrimitive)]
#[repr(u8)]
pub enum TcpState {
    /// The listening state, waiting for incoming connection requests.
    Listen,
    /// The state after sending a SYN message, awaiting acknowledgment.
    SynSent,
    /// The state after receiving a SYN+ACK message, awaiting final acknowledgment.
    SynReceived,
    /// The state after completing the three-way handshake; the connection is established.
    Established,
    /// The state where the connection is in the process of being closed (after sending FIN).
    FinWait1,
    /// The state where the other side has acknowledged the connection termination.
    FinWait2,
    /// The state after receiving a FIN message, waiting for acknowledgment from the other side.
    CloseWait,
    /// The state where the connection is actively closing (waiting for all data to be sent/acknowledged).
    Closing,
    /// The state where the sender has sent the final FIN message and is waiting for acknowledgment from the other side.
    LastAck,
    /// The state after both sides have sent FIN messages, indicating the connection is fully closed.
    TimeWait,
    /// The state where the connection is completely closed.
    Closed,
}

#[derive(Debug)]
pub struct Tcb {
    state: TcpState,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    // Send snd_seq to the other party
    snd_seq: SeqNum,
    // Send snd_ack to the other party
    snd_ack: AckNum,
    last_snd_ack: AckNum,
    // Received ordered maximum seq
    // rcv_seq: SeqNum,
    // Received ack,Its starting point is snd_seq
    rcv_ack: AckNum,
    snd_wnd: u16,
    rcv_wnd: u16,
    mss: u16,
    sack_permitted: bool,
    snd_window_shift_cnt: u8,
    rcv_window_shift_cnt: u8,
    duplicate_ack_count: usize,
    tcp_receive_queue: TcpReceiveQueue,
    tcp_out_of_order_queue: TcpOfoQueue,
    back_seq: Option<SeqNum>,
    inflight_packets: VecDeque<InflightPacket>,
    time_wait: Option<Instant>,
    time_wait_timeout: Duration,
    write_timeout: Option<Instant>,
    retransmission_timeout: Duration,
    timeout_count: (AckNum, usize),
    congestion_window: CongestionWindow,
    last_snd_wnd: u16,
    requires_ack_repeat: bool,
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
#[repr(transparent)]
struct SeqNum(u32);

type AckNum = SeqNum;

impl From<u32> for SeqNum {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SeqNum> for u32 {
    fn from(value: SeqNum) -> Self {
        value.0
    }
}

impl PartialOrd for SeqNum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SeqNum {
    fn cmp(&self, other: &Self) -> Ordering {
        let diff = self.0.wrapping_sub(other.0);
        if diff == 0 {
            Ordering::Equal
        } else if diff < MAX_DIFF {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }
}

impl Add for SeqNum {
    type Output = SeqNum;

    fn add(self, rhs: Self) -> Self::Output {
        SeqNum(self.0.wrapping_add(rhs.0))
    }
}

impl Sub for SeqNum {
    type Output = SeqNum;

    fn sub(self, rhs: Self) -> Self::Output {
        SeqNum(self.0.wrapping_sub(rhs.0))
    }
}

impl SeqNum {
    fn add_num(self, n: u32) -> Self {
        SeqNum(self.0.wrapping_add(n))
    }
    fn add_update(&mut self, n: u32) {
        self.0 = self.0.wrapping_add(n)
    }
}

#[derive(Debug)]
pub(crate) struct UnreadPacket {
    seq: SeqNum,
    flags: u8,
    payload: BytesMut,
}

impl Eq for UnreadPacket {}

impl PartialEq<Self> for UnreadPacket {
    fn eq(&self, other: &Self) -> bool {
        self.seq.eq(&other.seq)
    }
}

impl PartialOrd<Self> for UnreadPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UnreadPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.seq.cmp(&other.seq)
    }
}

impl UnreadPacket {
    fn new(seq: SeqNum, flags: u8, payload: BytesMut) -> Self {
        Self { seq, flags, payload }
    }
    pub(crate) fn len(&self) -> usize {
        if self.flags & FIN == FIN {
            self.payload.len() + 1
        } else {
            self.payload.len()
        }
    }
    fn advance(&mut self, cnt: usize) {
        self.seq.add_update(cnt as u32);
        self.payload.advance(cnt)
    }
    fn start(&self) -> SeqNum {
        self.seq
    }
    fn end(&self) -> SeqNum {
        self.seq.add_num(self.payload.len() as u32)
    }
    fn into_bytes(self) -> BytesMut {
        self.payload
    }
}

#[derive(Debug)]
struct InflightPacket {
    seq: SeqNum,
    // Need to support SACK
    confirmed: bool,
    buf: FixedBuffer,
}

impl InflightPacket {
    pub fn new(seq: SeqNum, buf: FixedBuffer) -> Self {
        let mut packet = Self {
            seq,
            confirmed: false,
            buf,
        };
        packet.init();
        packet
    }
    pub fn init(&mut self) {
        self.buf.clear();
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn advance(&mut self, cnt: usize) {
        self.seq.add_update(cnt as u32);
        self.buf.advance(cnt)
    }
    pub fn start(&self) -> SeqNum {
        self.seq
    }
    pub fn end(&self) -> SeqNum {
        self.seq.add_num(self.buf.len() as u32)
    }
    pub fn write(&mut self, buf: &[u8]) -> usize {
        self.buf.extend_from_slice(buf)
    }
    pub fn bytes(&self) -> &[u8] {
        self.buf.bytes()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TcpConfig {
    pub retransmission_timeout: Duration,
    pub time_wait_timeout: Duration,
    pub mss: Option<u16>,
    pub rcv_wnd: u16,
    pub window_shift_cnt: u8,
    pub quick_end: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            retransmission_timeout: Duration::from_millis(1000),
            time_wait_timeout: Duration::from_secs(10),
            mss: None,
            rcv_wnd: u16::MAX,
            // Window size too large can cause packet loss
            window_shift_cnt: 2,
            // If the stream is closed, exit the corresponding task immediately
            quick_end: true,
        }
    }
}

impl TcpConfig {
    pub fn check(&self) -> io::Result<()> {
        if let Some(mss) = self.mss {
            if mss < MSS_MIN {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "mss cannot be less than 536"));
            }
        }

        if self.retransmission_timeout.is_zero() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "retransmission_timeout is zero"));
        }
        Ok(())
    }
}

/// Implementation related to initialization connection
impl Tcb {
    pub fn new_listen(local_addr: SocketAddr, peer_addr: SocketAddr, config: TcpConfig) -> Self {
        let snd_seq = SeqNum::from(rand::rng().next_u32());
        Self {
            state: TcpState::Listen,
            local_addr,
            peer_addr,
            snd_seq,
            snd_ack: AckNum::from(0),
            last_snd_ack: AckNum::from(0),
            snd_wnd: 0,
            rcv_wnd: config.rcv_wnd,
            rcv_ack: snd_seq,
            mss: config.mss.unwrap_or(MSS_MIN),
            sack_permitted: false,
            snd_window_shift_cnt: 0,
            rcv_window_shift_cnt: config.window_shift_cnt,
            duplicate_ack_count: 0,
            // rcv_seq: SeqNum(0),
            tcp_receive_queue: Default::default(),
            tcp_out_of_order_queue: Default::default(),
            back_seq: None,
            inflight_packets: Default::default(),
            time_wait: None,
            time_wait_timeout: config.time_wait_timeout,
            write_timeout: None,
            retransmission_timeout: config.retransmission_timeout,
            timeout_count: (AckNum::from(0), 0),
            congestion_window: CongestionWindow::default(),
            last_snd_wnd: 0,
            requires_ack_repeat: false,
        }
    }
    pub fn try_syn_sent(&mut self) -> Option<TransportPacket> {
        if self.state == TcpState::Listen || self.state == TcpState::SynSent {
            self.sent_syn();
            let options = self.get_options();
            let packet = self.create_option_transport_packet(SYN, &[], Some(&options));
            Some(packet)
        } else {
            None
        }
    }
    pub fn try_syn_received(&mut self, tcp_packet: &TcpPacket<'_>) -> Option<TransportPacket> {
        let flags = tcp_packet.get_flags();
        if flags & RST == RST {
            self.recv_rst();
            return None;
        }
        if self.state == TcpState::Listen || self.state == TcpState::SynReceived {
            self.option(tcp_packet);
            self.snd_ack = AckNum::from(tcp_packet.get_sequence()).add_num(1);
            self.last_snd_ack = self.snd_ack;
            // self.rcv_seq = self.snd_ack;
            self.snd_wnd = tcp_packet.get_window();
            self.recv_syn();
            let options = self.get_options();
            let relay = self.create_option_transport_packet(SYN | ACK, &[], Some(&options));
            Some(relay)
        } else {
            None
        }
    }
    pub fn try_syn_received_to_established(&mut self, mut buf: BytesMut) -> bool {
        let Some(packet) = TcpPacket::new(&buf) else {
            self.error();
            return false;
        };
        let flags = packet.get_flags();
        if flags & RST == RST {
            self.recv_rst();
            return false;
        }
        let header_len = packet.get_data_offset() as usize * 4;
        let flags = packet.get_flags();
        if self.state == TcpState::SynReceived
            && flags & ACK == ACK
            && self.snd_ack.0 == packet.get_sequence()
            && self.snd_seq.add_num(1).0 == packet.get_acknowledgement()
        {
            self.snd_wnd = packet.get_window();
            self.snd_seq = SeqNum(packet.get_acknowledgement());
            self.rcv_ack = SeqNum(packet.get_acknowledgement());
            self.recv_syn_ack();
            self.init_congestion_window();
            if !packet.payload().is_empty() {
                let seq = SeqNum(packet.get_sequence());
                buf.advance(header_len);
                let unread_packet = UnreadPacket::new(seq, flags, buf);
                self.recv(unread_packet)
            }
            return true;
        }
        false
    }
    pub fn try_syn_sent_to_established(&mut self, buf: BytesMut) -> Option<TransportPacket> {
        let packet = TcpPacket::new(&buf)?;
        let flags = packet.get_flags();
        if self.state == TcpState::SynSent && flags & ACK == ACK && flags & SYN == SYN {
            self.snd_seq.add_update(1);
            self.snd_ack = SeqNum::from(packet.get_sequence()).add_num(1);
            self.last_snd_ack = self.snd_ack;
            self.rcv_ack = SeqNum(packet.get_acknowledgement());
            self.snd_wnd = packet.get_window();
            self.recv_syn_ack();
            self.init_congestion_window();
            let relay = self.create_option_transport_packet(ACK, &[], None);
            return Some(relay);
        }
        None
    }
    fn init_congestion_window(&mut self) {
        let initial_cwnd = self.mss as usize * 4;
        let max_cwnd = (self.snd_wnd as usize) << self.snd_window_shift_cnt;
        self.congestion_window
            .init(initial_cwnd, (initial_cwnd + max_cwnd) / 2, max_cwnd, self.mss as usize);
    }
}

impl Tcb {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
    pub fn mss(&self) -> u16 {
        self.mss
    }
    fn get_options(&self) -> BytesMut {
        let mut options = BytesMut::with_capacity(40);
        let mss = self.mss;
        options.put_u8(TcpOptionNumbers::MSS.0);
        options.put_u8(4);
        options.put_u16(mss);

        options.put_u8(TcpOptionNumbers::NOP.0);
        options.put_u8(TcpOptionNumbers::WSCALE.0);
        options.put_u8(3);
        options.put_u8(self.rcv_window_shift_cnt);
        options.put_u8(TcpOptionNumbers::NOP.0);
        options.put_u8(TcpOptionNumbers::NOP.0);
        options.put_u8(TcpOptionNumbers::SACK_PERMITTED.0);
        options.put_u8(2);
        options
    }
    fn option(&mut self, tcp_packet: &TcpPacket<'_>) {
        for tcp_option in tcp_packet.get_options_iter() {
            let payload = tcp_option.payload();
            match tcp_option.get_number() {
                TcpOptionNumbers::WSCALE => {
                    if let Some(window_shift_cnt) = payload.first() {
                        self.snd_window_shift_cnt = (*window_shift_cnt).min(14);
                    }
                }
                TcpOptionNumbers::MSS => {
                    if payload.len() == 2 {
                        self.mss = (payload[0] as u16) << 8 | (payload[1] as u16);
                    }
                }
                TcpOptionNumbers::SACK_PERMITTED => {
                    // Selective acknowledgements permitted.
                    self.sack_permitted = true;
                }
                TcpOptionNumber(_) => {}
            }
        }
    }
    fn option_sack(&mut self, tcp_packet: &TcpPacket<'_>) {
        if !self.sack_permitted {
            return;
        }
        for tcp_option in tcp_packet.get_options_iter() {
            if tcp_option.get_number() == TcpOptionNumbers::SACK {
                let payload = tcp_option.payload();
                if payload.len() & 7 != 0 {
                    continue;
                }
                let n = payload.len() >> 3;
                for inflight_packet in self.inflight_packets.iter_mut() {
                    for index in 0..n {
                        let offset = index * 8;
                        let left: SeqNum = payload[offset..4 + offset].try_into().map(u32::from_be_bytes).unwrap().into();
                        let right: SeqNum = payload[4 + offset..8 + offset].try_into().map(u32::from_be_bytes).unwrap().into();
                        if inflight_packet.confirmed || inflight_packet.end() <= left {
                            break;
                        }
                        if inflight_packet.start() >= left && inflight_packet.end() <= right {
                            inflight_packet.confirmed = true;
                        }
                    }
                }
            }
        }
    }
    fn create_transport_packet(&self, flags: u8, payload: &[u8]) -> TransportPacket {
        let data = self.create_packet(flags, self.snd_seq.0, self.snd_ack.0, payload, None);
        TransportPacket::new(data, NetworkTuple::new(self.local_addr, self.peer_addr, IpNextHeaderProtocols::Tcp))
    }
    fn create_option_transport_packet(&self, flags: u8, payload: &[u8], options: Option<&[u8]>) -> TransportPacket {
        let data = self.create_packet(flags, self.snd_seq.0, self.snd_ack.0, payload, options);
        TransportPacket::new(data, NetworkTuple::new(self.local_addr, self.peer_addr, IpNextHeaderProtocols::Tcp))
    }
    fn create_transport_packet_seq(&self, flags: u8, seq: u32, payload: &[u8]) -> TransportPacket {
        let data = self.create_packet(flags, seq, self.snd_ack.0, payload, None);
        TransportPacket::new(data, NetworkTuple::new(self.local_addr, self.peer_addr, IpNextHeaderProtocols::Tcp))
    }

    fn create_packet(&self, flags: u8, seq: u32, ack: u32, payload: &[u8], options: Option<&[u8]>) -> BytesMut {
        create_packet_raw(
            &self.local_addr,
            &self.peer_addr,
            seq,
            ack,
            self.recv_window(),
            flags,
            payload,
            options,
        )
    }
}

/// Implementation related to reading data
impl Tcb {
    pub fn readable_state(&self) -> bool {
        matches!(self.state, TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2)
    }
    pub fn cannot_read(&self) -> bool {
        !self.readable_state() && !self.readable()
    }

    pub fn push_packet(&mut self, mut buf: BytesMut) -> Option<TransportPacket> {
        let Some(packet) = TcpPacket::new(&buf) else {
            self.error();
            return None;
        };
        let flags = packet.get_flags();
        if flags & RST == RST {
            self.recv_rst();
            return None;
        }
        if flags & SYN == SYN {
            let reply_packet = self.create_transport_packet(RST, &[]);
            return Some(reply_packet);
        }

        let header_len = packet.get_data_offset() as usize * 4;
        match self.state {
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                if flags & ACK == ACK {
                    let acknowledgement = AckNum::from(packet.get_acknowledgement());
                    if acknowledgement == self.rcv_ack {
                        if self.rcv_ack != self.snd_seq {
                            self.duplicate_ack_count += 1;
                            if self.duplicate_ack_count > 3 {
                                self.back_n();
                            }
                        }
                        self.snd_wnd = packet.get_window();
                    }

                    self.update_last_ack(&packet);
                    self.option_sack(&packet);
                }
                let seq = SeqNum(packet.get_sequence());
                buf.advance(header_len);
                let unread_packet = UnreadPacket::new(seq, flags, buf);
                if self.rcv_wnd == 0 {
                    self.snd_ack = unread_packet.end();
                }
                if self.recv_buffer_full() {
                    // Packet loss occurs when the buffer is full
                    return None;
                }
                if unread_packet.end() >= self.snd_ack {
                    self.recv(unread_packet);
                }
                return None;
            }
            TcpState::CloseWait | TcpState::Closing | TcpState::LastAck | TcpState::TimeWait => {
                if flags & ACK == ACK {
                    let acknowledgement = AckNum::from(packet.get_acknowledgement());
                    if acknowledgement > self.snd_seq {
                        // acknowledgement == self.snd_seq + 1
                        self.recv_fin_ack()
                    }
                }
                if flags & FIN == FIN {
                    self.recv_fin();
                    // reply ACK
                    let reply_packet = self.create_transport_packet(ACK, &[]);
                    return Some(reply_packet);
                }
                return None;
            }
            _ => {
                // RST
            }
        }
        self.error();
        let reply_packet = self.create_transport_packet(RST, &[]);
        Some(reply_packet)
    }
    pub fn readable(&self) -> bool {
        self.tcp_receive_queue.total_bytes() != 0
    }
    pub fn read_none(&mut self) {
        self.rcv_wnd = 0;
        self.tcp_receive_queue.clear();
    }
    pub fn read(&mut self) -> Option<BytesMut> {
        self.tcp_receive_queue.pop()
    }

    fn recv(&mut self, mut unread_packet: UnreadPacket) {
        let start = unread_packet.start();
        if self.snd_ack >= start {
            let flags = unread_packet.flags;
            let end = unread_packet.end();
            if end > self.snd_ack {
                unread_packet.advance((self.snd_ack - start).0 as usize);
                self.snd_ack = end;
                self.tcp_receive_queue.push(unread_packet.into_bytes())
            }
            if flags & FIN == FIN {
                self.recv_fin();
            }
        } else {
            self.tcp_out_of_order_queue.push(unread_packet);
            self.advice_ack();
            if !self.tcp_out_of_order_queue.is_empty() {
                // If out-of-order packets are present, a duplicate ACK is required to trigger the peer's fast retransmit.
                self.requires_ack_repeat = true;
            }
        }
    }
    fn advice_ack(&mut self) {
        while let Some(packet) = self.tcp_out_of_order_queue.peek() {
            let start = packet.start();
            if self.snd_ack < start {
                //unordered
                break;
            }
            let flags = packet.flags;
            let end = packet.end();
            let mut unread_packet = self.tcp_out_of_order_queue.pop().unwrap();
            if end > self.snd_ack {
                let offset = (self.snd_ack - start).0;
                self.snd_ack = end;
                unread_packet.advance(offset as usize);
                self.tcp_receive_queue.push(unread_packet.into_bytes());
            }
            if flags & FIN == FIN {
                self.recv_fin();
                break;
            }
        }
    }
    pub fn need_ack(&self) -> bool {
        self.last_snd_wnd != self.recv_window() || self.snd_ack != self.last_snd_ack || self.requires_ack_repeat
    }
    pub fn recv_window(&self) -> u16 {
        let src_rcv_wnd = (self.rcv_wnd as usize) << self.rcv_window_shift_cnt;
        let unread_total_bytes = self.tcp_out_of_order_queue.total_bytes() + self.tcp_receive_queue.total_bytes();
        let rcv_wnd = src_rcv_wnd.saturating_sub(unread_total_bytes);
        (rcv_wnd >> self.rcv_window_shift_cnt) as u16
    }
    fn recv_buffer_full(&self) -> bool {
        // To reduce packet loss, the actual receivable window size is larger than the recv_window()
        let src_rcv_wnd = ((self.rcv_wnd as usize) << self.rcv_window_shift_cnt) << 1;
        let unread_total_bytes = self.tcp_out_of_order_queue.total_bytes() + self.tcp_receive_queue.total_bytes();
        src_rcv_wnd <= unread_total_bytes
    }
    // pub fn recv_busy(&self) -> bool {
    //     if !self.readable_state() || self.rcv_wnd == 0 {
    //         return false;
    //     }
    //     let src_rcv_wnd = (self.rcv_wnd as usize) << self.rcv_window_shift_cnt;
    //     let unread_total_bytes = self.tcp_out_of_order_queue.total_bytes() + self.tcp_receive_queue.total_bytes();
    //     let rcv_wnd = src_rcv_wnd.saturating_sub(unread_total_bytes);
    //     rcv_wnd <= 2 * self.mss as usize
    // }
}

/// Implementation related to writing data
impl Tcb {
    #[inline]
    fn ack_distance(&self) -> u32 {
        (self.snd_seq - self.rcv_ack).0
    }
    fn send_window(&self) -> usize {
        let distance = self.ack_distance();
        let snd_wnd = (self.snd_wnd as usize) << self.snd_window_shift_cnt;
        let wnd = self.congestion_window.current_window_size().min(snd_wnd);
        // log::info!("snd_wnd1 ={snd_wnd1} snd_wnd = {snd_wnd:?},distance={distance}");
        wnd.saturating_sub(distance as usize)
    }

    pub fn perform_post_ack_action(&mut self) {
        self.last_snd_wnd = self.recv_window();
        self.last_snd_ack = self.snd_ack;
        self.requires_ack_repeat = false;
    }
    fn update_last_ack(&mut self, tcp_packet: &TcpPacket<'_>) {
        let ack = AckNum::from(tcp_packet.get_acknowledgement());
        if ack <= self.rcv_ack {
            return;
        }
        self.snd_wnd = tcp_packet.get_window();
        self.congestion_window.on_ack();
        self.duplicate_ack_count = 0;
        let mut distance = (ack - self.rcv_ack).0 as usize;
        self.rcv_ack = ack;
        while let Some(inflight_packet) = self.inflight_packets.front_mut() {
            if inflight_packet.len() > distance {
                inflight_packet.advance(distance);
                break;
            } else {
                distance -= inflight_packet.len();
                _ = self.inflight_packets.pop_front();
            }
        }
        if self.inflight_packets.is_empty() {
            self.write_timeout.take();
        } else if let Some(write_timeout) = self.write_timeout.as_mut() {
            *write_timeout += self.retransmission_timeout
        }
        if !self.writeable_state() && self.rcv_ack > self.snd_seq {
            self.recv_fin_ack()
        }
        self.reset_write_timeout();
    }
    fn take_send_buf(&mut self) -> Option<InflightPacket> {
        let bytes_mut = FixedBuffer::with_capacity(self.mss as usize);
        Some(InflightPacket::new(self.snd_seq, bytes_mut))
    }
    pub fn write(&mut self, buf: &[u8]) -> Option<(TransportPacket, usize)> {
        let rs = self.write0(buf);
        self.init_write_timeout();
        rs
    }
    fn write0(&mut self, mut buf: &[u8]) -> Option<(TransportPacket, usize)> {
        if !self.writeable_state() {
            return None;
        }
        let seq = self.snd_seq.0;
        let snd_wnd = self.send_window();
        if snd_wnd < buf.len() {
            buf = &buf[..snd_wnd];
        }
        if buf.is_empty() {
            return None;
        }
        let flags = if self.decelerate() { PSH | ACK } else { ACK };
        if let Some(packet) = self.inflight_packets.back_mut() {
            let n = packet.write(buf);
            if n > 0 {
                let packet = self.create_transport_packet_seq(flags, seq, &buf[..n]);
                self.snd_seq.add_update(n as u32);
                return Some((packet, n));
            }
        }

        if let Some(mut packet) = self.take_send_buf() {
            let n = packet.write(buf);
            assert!(n > 0);
            self.inflight_packets.push_back(packet);
            let packet = self.create_transport_packet_seq(flags, seq, &buf[..n]);
            self.snd_seq.add_update(n as u32);
            return Some((packet, n));
        }
        None
    }
    pub fn write_timeout(&self) -> Option<Instant> {
        self.write_timeout
    }
    fn reset_write_timeout(&mut self) {
        if !self.inflight_packets.is_empty() {
            self.write_timeout.replace(Instant::now() + self.retransmission_timeout);
        }
    }
    fn init_write_timeout(&mut self) {
        if self.write_timeout.is_none() {
            self.reset_write_timeout();
        }
    }

    pub fn retransmission(&mut self) -> Option<TransportPacket> {
        let back_seq = self.back_seq?;
        for packet in self.inflight_packets.iter() {
            if packet.confirmed {
                continue;
            }
            if packet.end() > back_seq {
                self.back_seq.replace(packet.end());
                return Some(self.create_transport_packet_seq(ACK, packet.start().0, packet.bytes()));
            }
        }
        self.back_seq.take();
        None
    }
    fn back_n(&mut self) -> bool {
        if let Some(v) = self.inflight_packets.front() {
            self.back_seq.replace(v.start());
            self.congestion_window.on_loss();
            self.reset_write_timeout();
            true
        } else {
            false
        }
    }
    pub fn decelerate(&self) -> bool {
        let snd_wnd = self.send_window();
        snd_wnd <= (self.mss as usize) << 4
    }
    pub fn limit(&self) -> bool {
        let snd_wnd = self.send_window();
        snd_wnd == 0
    }
    pub fn no_inflight_packet(&self) -> bool {
        self.inflight_packets.is_empty()
    }
    pub fn writeable_state(&self) -> bool {
        self.state == TcpState::Established || self.state == TcpState::CloseWait
    }
    pub fn cannot_write(&self) -> bool {
        !self.writeable_state()
    }
    pub fn is_close(&self) -> bool {
        self.state == TcpState::Closed
    }
    pub fn time_wait(&self) -> Option<Instant> {
        self.time_wait
    }
    pub fn timeout(&mut self) {
        if self.state == TcpState::TimeWait {
            self.timeout_wait();
            return;
        }
        if !self.back_n() {
            return;
        }
        if self.timeout_count.0 == self.rcv_ack {
            self.timeout_count.1 += 1;
            if self.timeout_count.1 > 10 {
                self.error();
            }
        } else {
            self.timeout_count.0 = self.rcv_ack;
            self.timeout_count.1 = 0;
        }
    }
    pub fn need_retransmission(&self) -> bool {
        self.back_seq.is_some()
    }
}

/// TCP state rotation
impl Tcb {
    fn sent_syn(&mut self) {
        if self.state == TcpState::Listen {
            self.state = TcpState::SynSent
        }
    }
    fn recv_syn(&mut self) {
        if self.state == TcpState::Listen {
            self.state = TcpState::SynReceived
        }
    }
    fn recv_syn_ack(&mut self) {
        match self.state {
            TcpState::SynReceived => self.state = TcpState::Established,
            TcpState::SynSent => self.state = TcpState::Established,
            _ => {}
        }
    }

    pub fn sent_fin(&mut self) {
        match self.state {
            TcpState::Established => self.state = TcpState::FinWait1,
            TcpState::CloseWait => self.state = TcpState::LastAck,
            _ => {}
        }
    }
    fn recv_fin(&mut self) {
        match self.state {
            TcpState::Established => {
                self.snd_ack.add_update(1);
                self.state = TcpState::CloseWait
            }
            TcpState::FinWait1 => {
                self.snd_ack.add_update(1);
                self.state = TcpState::Closing
            }
            TcpState::FinWait2 => {
                self.snd_ack.add_update(1);
                self.time_wait = Some(Instant::now() + self.time_wait_timeout);
                self.state = TcpState::TimeWait
            }
            _ => {}
        }
    }
    fn recv_fin_ack(&mut self) {
        match self.state {
            TcpState::FinWait1 => self.state = TcpState::FinWait2,
            TcpState::Closing => self.state = TcpState::TimeWait,
            TcpState::LastAck => self.state = TcpState::Closed,
            _ => {}
        }
    }
    fn recv_rst(&mut self) {
        self.state = TcpState::Closed
    }
    fn timeout_wait(&mut self) {
        assert_eq!(self.state, TcpState::TimeWait);
        self.state = TcpState::Closed
    }
    fn error(&mut self) {
        self.state = TcpState::Closed
    }
    pub fn fin_packet(&self) -> TransportPacket {
        let seq = self.snd_seq.0;
        self.create_transport_packet_seq(FIN | ACK, seq, &[])
    }
    pub fn ack_packet(&self) -> TransportPacket {
        let seq = self.snd_seq.0;
        self.create_transport_packet_seq(ACK, seq, &[])
    }
}

pub fn create_transport_packet_raw(
    local_addr: &SocketAddr,
    peer_addr: &SocketAddr,
    snd_seq: u32,
    rcv_ack: u32,
    rcv_wnd: u16,
    flags: u8,
    payload: &[u8],
) -> TransportPacket {
    let data = create_packet_raw(local_addr, peer_addr, snd_seq, rcv_ack, rcv_wnd, flags, payload, None);
    TransportPacket::new(data, NetworkTuple::new(*local_addr, *peer_addr, IpNextHeaderProtocols::Tcp))
}

#[allow(clippy::too_many_arguments)]
pub fn create_packet_raw(
    local_addr: &SocketAddr,
    peer_addr: &SocketAddr,
    snd_seq: u32,
    snd_ack: u32,
    rcv_wnd: u16,
    flags: u8,
    payload: &[u8],
    options: Option<&[u8]>,
) -> BytesMut {
    let mut bytes = BytesMut::with_capacity(TCP_HEADER_LEN + payload.len());
    bytes.put_u16(local_addr.port());
    bytes.put_u16(peer_addr.port());
    bytes.put_u32(snd_seq);
    bytes.put_u32(snd_ack);
    let head_len = options
        .filter(|op| !op.is_empty())
        .map(|op| {
            assert_eq!(op.len() & 3, 0, "Options must be aligned with four bytes");
            TCP_HEADER_LEN + op.len()
        })
        .unwrap_or(TCP_HEADER_LEN);
    // Data Offset
    bytes.put_u8((head_len as u8 / 4) << 4);
    bytes.put_u8(flags);
    bytes.put_u16(rcv_wnd);
    // Checksum
    bytes.put_u16(0);
    // Urgent Pointer
    bytes.put_u16(0);
    if let Some(op) = options {
        if !op.is_empty() {
            bytes.extend_from_slice(op);
        }
    }
    bytes.extend_from_slice(payload);
    let checksum = match (local_addr.ip(), peer_addr.ip()) {
        (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
            pnet_packet::util::ipv4_checksum(&bytes, 8, &[], &src_ip, &dst_ip, IpNextHeaderProtocols::Tcp)
        }
        (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
            pnet_packet::util::ipv6_checksum(&bytes, 8, &[], &src_ip, &dst_ip, IpNextHeaderProtocols::Tcp)
        }
        (_, _) => {
            unreachable!()
        }
    };
    bytes[16..18].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

#[derive(Copy, Clone, Debug, Default)]
struct CongestionWindow {
    cwnd: usize,
    ssthresh: usize,
    max_cwnd: usize,
    mss: usize,
}

impl CongestionWindow {
    pub fn init(&mut self, initial_cwnd: usize, initial_ssthresh: usize, max_cwnd: usize, mss: usize) {
        self.cwnd = initial_cwnd;
        self.ssthresh = initial_ssthresh;
        self.max_cwnd = max_cwnd;
        self.mss = mss;
    }

    pub fn on_ack(&mut self) {
        if self.cwnd < self.ssthresh {
            self.cwnd *= 2;
        } else {
            self.cwnd += (self.cwnd as f64).sqrt() as usize;
        }

        self.cwnd = self.cwnd.min(self.max_cwnd);
    }

    pub fn on_loss(&mut self) {
        self.ssthresh = self.cwnd / 2;
        self.cwnd = self.mss;
    }

    pub fn current_window_size(&self) -> usize {
        self.cwnd
    }
}
