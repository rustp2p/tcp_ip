use crate::buffer::FixedBuffer;
use crate::ip_stack::{NetworkTuple, TransportPacket};
use crate::tcp::tcp_ofo_queue::TcpOfoQueue;
use bytes::{Buf, BufMut, BytesMut};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::TcpFlags::{ACK, FIN, PSH, RST, SYN};
use pnet_packet::tcp::{TcpOptionNumber, TcpOptionNumbers, TcpPacket};
use pnet_packet::Packet;
use rand::RngCore;
use std::cmp::Ordering;
use std::collections::{BTreeMap, LinkedList, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::{Add, Sub};
use std::time::{Duration, Instant};

const IP_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const IP_TCP_HEADER_LEN: usize = IP_HEADER_LEN + TCP_HEADER_LEN;
const MAX_DIFF: u32 = u32::MAX / 2;
const MAX_PACKETS: usize = 256;

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
    snd_window_shift_cnt: u8,
    rcv_window_shift_cnt: u8,
    duplicate_ack_count: usize,
    ordered_packets: LinkedList<UnreadPacket>,
    unordered_packets: TcpOfoQueue<UnreadPacket>,
    back_seq: Option<SeqNum>,
    inflight_packets: VecDeque<InflightPacket>,
    time_wait: Option<Instant>,
    write_timeout: Option<Instant>,
    retransmission_timeout: Duration,
    timeout_count: (AckNum, usize),
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

impl Into<u32> for SeqNum {
    fn into(self) -> u32 {
        self.0
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
    fn sub_num(self, n: u32) -> Self {
        SeqNum(self.0.wrapping_sub(n))
    }
    fn add_update(&mut self, n: u32) {
        self.0 = self.0.wrapping_add(n)
    }
    fn sub_update(&mut self, n: u32) {
        self.0 = self.0.wrapping_sub(n)
    }
}

#[derive(Debug)]
struct UnreadPacket {
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
        self.seq.partial_cmp(&other.seq)
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
}

#[derive(Debug)]
struct InflightPacket {
    seq: u32,
    buf: FixedBuffer,
}

impl InflightPacket {
    pub fn new(seq: u32, buf: FixedBuffer) -> Self {
        let mut packet = Self { seq, buf };
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
        self.seq = self.seq.wrapping_add(cnt as u32);
        self.buf.advance(cnt)
    }
    pub fn start(&self) -> u32 {
        self.seq
    }
    pub fn end(&self) -> u32 {
        self.seq.wrapping_add(self.buf.len() as u32)
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
    pub mss: u16,
    pub window_shift_cnt: u8,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            retransmission_timeout: Duration::from_millis(1000),
            mss: 536,
            window_shift_cnt: 0,
        }
    }
}

impl TcpConfig {
    pub fn check(&self) -> io::Result<()> {
        if self.mss < 536 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "mss cannot be less than 536"));
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
        let snd_seq = SeqNum::from(rand::thread_rng().next_u32());
        Self {
            state: TcpState::Listen,
            local_addr,
            peer_addr,
            snd_seq,
            snd_ack: AckNum::from(0),
            last_snd_ack: AckNum::from(0),
            snd_wnd: 0,
            rcv_wnd: u16::MAX,
            rcv_ack: snd_seq,
            mss: config.mss,
            snd_window_shift_cnt: 0,
            rcv_window_shift_cnt: config.window_shift_cnt,
            duplicate_ack_count: 0,
            // rcv_seq: SeqNum(0),
            ordered_packets: Default::default(),
            unordered_packets: Default::default(),
            back_seq: None,
            inflight_packets: Default::default(),
            time_wait: None,
            write_timeout: None,
            retransmission_timeout: config.retransmission_timeout,
            timeout_count: (AckNum::from(0), 0),
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
        if self.state == TcpState::SynReceived {
            if flags & ACK == ACK && self.snd_ack.0 == packet.get_sequence() && self.snd_seq.add_num(1).0 == packet.get_acknowledgement() {
                self.snd_wnd = packet.get_window();
                self.snd_seq = SeqNum(packet.get_acknowledgement());
                self.rcv_ack = SeqNum(packet.get_acknowledgement());
                self.recv_syn_ack();
                if !packet.payload().is_empty() {
                    let seq = SeqNum(packet.get_sequence());
                    buf.advance(header_len);
                    self.recv(seq, flags, buf)
                }
                return true;
            }
        }
        false
    }
    pub fn try_syn_sent_to_established(&mut self, mut buf: BytesMut) -> Option<TransportPacket> {
        let Some(packet) = TcpPacket::new(&buf) else {
            self.error();
            return None;
        };
        let flags = packet.get_flags();
        if self.state == TcpState::SynSent {
            if flags & ACK == ACK && flags & SYN == SYN {
                self.snd_seq.add_update(1);
                self.snd_ack = SeqNum::from(packet.get_sequence()).add_num(1);
                self.last_snd_ack = self.snd_ack;
                self.rcv_ack = SeqNum(packet.get_acknowledgement());
                self.snd_wnd = packet.get_window();
                self.recv_syn_ack();
                let relay = self.create_option_transport_packet(ACK, &[], None);
                return Some(relay);
            }
        }
        None
    }
}

impl Tcb {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
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
        // todo TCP Option - SACK permitted
        options
    }
    fn option(&mut self, tcp_packet: &TcpPacket<'_>) {
        for tcp_option in tcp_packet.get_options_iter() {
            let payload = tcp_option.payload();
            match tcp_option.get_number() {
                TcpOptionNumbers::WSCALE => {
                    if let Some(window_shift_cnt) = payload.get(0) {
                        self.snd_window_shift_cnt = (*window_shift_cnt).min(14);
                    }
                }
                TcpOptionNumbers::MSS => {
                    if payload.len() == 2 {
                        self.mss = (payload[0] as u16) << 8 | (payload[1] as u16);
                    }
                }
                TcpOptionNumber(_) => {
                    // todo Handle other options
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
    fn create_transport_packet_seq_ack(&self, flags: u8, seq: u32, ack: u32, payload: &[u8]) -> TransportPacket {
        let data = self.create_packet(flags, seq, ack, payload, None);
        TransportPacket::new(data, NetworkTuple::new(self.local_addr, self.peer_addr, IpNextHeaderProtocols::Tcp))
    }
    fn create_packet(&self, flags: u8, seq: u32, ack: u32, payload: &[u8], options: Option<&[u8]>) -> BytesMut {
        create_packet_raw(&self.local_addr, &self.peer_addr, seq, ack, self.rcv_wnd, flags, payload, options)
    }
}

/// Implementation related to reading data
impl Tcb {
    pub fn readable_state(&self) -> bool {
        match self.state {
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => true,
            _ => false,
        }
    }
    pub fn cannot_read(&self) -> bool {
        !self.readable_state()
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
        let header_len = packet.get_data_offset() as usize * 4;
        match self.state {
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                if flags & ACK == ACK {
                    self.snd_wnd = packet.get_window();
                    let acknowledgement = AckNum::from(packet.get_acknowledgement());
                    if acknowledgement == self.rcv_ack {
                        if self.rcv_ack != self.snd_seq {
                            self.duplicate_ack_count += 1;
                            if self.duplicate_ack_count > 3 {
                                self.back_n();
                            }
                        }
                    }

                    self.update_last_ack(acknowledgement)
                }
                let seq = SeqNum(packet.get_sequence());
                if seq >= self.snd_ack {
                    if flags & FIN == FIN && self.unordered_packets.is_empty() {
                        self.recv_fin();
                        let reply_packet = self.create_transport_packet(ACK, &[]);
                        return Some(reply_packet);
                    } else {
                        buf.advance(header_len);
                        self.recv(seq, flags, buf)
                    }
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
            }
            _ => {
                // RST
            } // TcpState::Listen => {}
              // TcpState::SynSent => {}
              // TcpState::SynReceived => {}
              // TcpState::Closing => {}
              // TcpState::LastAck => {}
              // TcpState::Closed => {}
        }
        self.error();
        let reply_packet = self.create_transport_packet(RST, &[]);
        return Some(reply_packet);
    }
    pub fn duplicate_ack_count(&self) -> usize {
        self.duplicate_ack_count
    }
    pub fn readable(&self) -> usize {
        if self.cannot_read() {
            return 0;
        }
        let mut len = 0;
        for packet in &self.unordered_packets {
            let seq = packet.seq;
            if self.snd_ack < seq {
                //unordered
                break;
            }

            let payload = &packet.payload;
            let offset = (self.snd_ack - seq).0 as usize;
            assert!(offset <= payload.len(), "{offset}<={}", payload.len());
            len += payload.len() - offset;
            let flags = packet.flags;

            if flags & FIN == FIN {
                len += 1;
                break;
            }
        }
        len
    }
    pub fn read_none(&mut self) {
        let mut fin = false;
        self.rcv_wnd = 0;
        while let Some(packet) = self.unordered_packets.peek() {
            let seq = packet.seq;
            let flags = packet.flags;
            let payload = &packet.payload;
            if self.snd_ack < seq {
                //unordered
                break;
            }

            let offset = (self.snd_ack - seq).0 as usize;
            if offset >= payload.len() {
                self.unordered_packets.pop();
            } else {
                let count = payload.len() - offset;
                self.snd_ack.add_update(count as u32);
                self.unordered_packets.pop();
            }
            if flags & FIN == FIN {
                fin = true;
                break;
            }
        }
        if fin {
            // Processing FIN flags
            self.recv_fin();
            self.unordered_packets.clear();
        }
    }
    pub fn read(&mut self, mut buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        let len = buf.len();
        let mut fin = false;
        while let Some(packet) = self.unordered_packets.peek() {
            let seq = packet.seq;
            let flags = packet.flags;
            let payload = &packet.payload;
            if self.snd_ack < seq {
                //unordered
                break;
            }

            let offset = (self.snd_ack - seq).0 as usize;
            if offset >= payload.len() {
                self.unordered_packets.pop();
            } else {
                let count = payload.len() - offset;
                let min = buf.len().min(count);
                buf[..min].copy_from_slice(&payload[offset..offset + min]);
                buf = &mut buf[min..];
                self.snd_ack = self.snd_ack.add_num(min as u32);
                if min == count {
                    self.unordered_packets.pop();
                }
            }

            if flags & FIN == FIN {
                fin = true;
                break;
            }
            if buf.is_empty() {
                break;
            }
        }
        if fin {
            // Processing FIN flags
            self.recv_fin();
            self.unordered_packets.clear();
        }
        len - buf.len()
    }

    fn recv(&mut self, seq: SeqNum, flags: u8, payload: BytesMut) {
        let unread_packet = UnreadPacket::new(seq, flags, payload);
        self.unordered_packets.push(unread_packet, handle_duplicate_seq);
    }
}

fn handle_duplicate_seq(p1: &UnreadPacket, p2: &UnreadPacket) -> bool {
    p1.payload.len() < p2.payload.len()
}

/// Implementation related to writing data
impl Tcb {
    #[inline]
    pub fn ack_distance(&self) -> u32 {
        (self.snd_seq - self.rcv_ack).0
    }
    pub fn send_window(&self) -> usize {
        let distance = self.ack_distance();
        let snd_wnd = (self.snd_wnd as usize) << self.snd_window_shift_cnt;
        snd_wnd.saturating_sub(distance as usize)
    }
    pub fn need_ack(&self) -> bool {
        self.snd_ack > self.last_snd_ack
    }
    pub fn set_ack(&mut self) {
        self.last_snd_ack = self.snd_ack;
    }
    fn update_last_ack(&mut self, ack: SeqNum) {
        if ack <= self.rcv_ack {
            return;
        }
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
            *write_timeout = *write_timeout + self.retransmission_timeout
        }
        if !self.writeable_state() && self.rcv_ack > self.snd_seq {
            self.recv_fin_ack()
        }
    }
    fn take_send_buf(&mut self) -> Option<InflightPacket> {
        if self.inflight_packets.len() >= MAX_PACKETS {
            None
        } else {
            let bytes_mut = FixedBuffer::with_capacity(self.mss as usize);
            Some(InflightPacket::new(self.snd_seq.0, bytes_mut))
        }
    }
    pub fn write(&mut self, buf: &[u8]) -> Option<(TransportPacket, usize)> {
        let rs = self.write0(buf);
        self.reset_write_timeout();
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
            let n = packet.write(&buf);
            if n > 0 {
                let packet = self.create_transport_packet_seq(flags, seq, &buf[..n]);
                self.snd_seq.add_update(n as u32);
                return Some((packet, n));
            }
        }

        if let Some(mut packet) = self.take_send_buf() {
            let n = packet.write(&buf);
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

    pub fn retransmission(&mut self) -> Option<TransportPacket> {
        let Some(back_seq) = self.back_seq else {
            return None;
        };
        for packet in self.inflight_packets.iter() {
            if packet.seq == back_seq.0 {
                self.back_seq.replace(back_seq.add_num(packet.len() as u32));
                return Some(self.create_transport_packet(ACK, packet.bytes()));
            }
        }
        self.back_seq.take();
        None
    }
    fn back_n(&mut self) {
        if !self.inflight_packets.is_empty() {
            self.reset_write_timeout();
            self.back_seq.replace(self.rcv_ack);
        }
    }
    pub fn decelerate(&self) -> bool {
        let distance = self.ack_distance();
        let snd_wnd = (self.snd_wnd as usize) << self.snd_window_shift_cnt;
        snd_wnd < 3 * distance as usize
    }
    pub fn limit(&self) -> bool {
        let distance = (self.snd_seq - self.rcv_ack).0;
        let snd_wnd = (self.snd_wnd as usize) << self.snd_window_shift_cnt;
        // window_shift_cnt doesn't seem to be effective,
        // Using snd_wnd may cause the other party to not receive it.
        // Perhaps it is because the 'slow start' of TCP congestion control has not been implemented
        snd_wnd < 2 * distance as usize
    }
    pub fn no_inflight_packet(&self) -> bool {
        self.inflight_packets.is_empty()
    }
    pub fn inflight_packet(&self) -> usize {
        self.inflight_packets.len()
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
        self.back_n();
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
                self.time_wait = Some(Instant::now() + Duration::from_secs(120));
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
