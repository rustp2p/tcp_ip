#![allow(dead_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::ops::{Add, Sub};

use bytes::{Buf, BufMut, BytesMut};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::TcpFlags::{ACK, FIN, PSH, RST, SYN};
use pnet_packet::tcp::{TcpOptionNumber, TcpOptionNumbers, TcpPacket};
use pnet_packet::Packet;
use rand::RngCore;

use crate::buffer::FixedBuffer;
use crate::ip_stack::{NetworkTuple, TransportPacket};

/// Enum representing the various states of a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub(crate) struct Tcb {
    common: Common,
    unordered_packets: BTreeMap<SeqNum, UnreadPacket>,
}

impl Tcb {
    pub fn new_listen(local_addr: SocketAddr, peer_addr: SocketAddr, mtu: u16) -> Self {
        let mut common = Common::new_listen(local_addr, peer_addr, mtu);
        Self {
            common,
            unordered_packets: Default::default(),
        }
    }
    pub fn try_syn_received(&mut self, tcp_packet: &TcpPacket<'_>) -> Option<TransportPacket> {
        let flags = tcp_packet.get_flags();
        if flags & RST == RST {
            self.common.state = TcpState::Closed;
            return None;
        }
        if self.common.state == TcpState::Listen || self.common.state == TcpState::SynReceived {
            self.common.option(tcp_packet);
            self.common.snd_ack = SeqNum(tcp_packet.get_sequence()).add_num(1);
            self.common.snd_wnd = tcp_packet.get_window();
            self.common.state = TcpState::SynReceived;
            let options = self.get_options();
            let relay = self.common.create_option_transport_packet(SYN | ACK, &[], Some(&options));
            Some(relay)
        } else {
            None
        }
    }
    fn get_options(&self) -> BytesMut {
        let mut options = BytesMut::with_capacity(40);
        let mss = self.common.mtu - IP_TCP_HEADER_LEN as u16;
        options.put_u8(TcpOptionNumbers::MSS.0);
        options.put_u8(4);
        options.put_u16(mss);

        options.put_u8(TcpOptionNumbers::NOP.0);
        if self.common.window_shift_cnt > 0 {
            options.put_u8(TcpOptionNumbers::WSCALE.0);
            options.put_u8(3);
            options.put_u8(self.common.window_shift_cnt);
        }
        // todo TCP Option - SACK permitted
        options
    }
    pub fn try_established(&mut self, mut buf: BytesMut) -> bool {
        let Some(packet) = TcpPacket::new(&buf) else {
            return false;
        };
        let flags = packet.get_flags();
        if flags & RST == RST {
            self.common.state = TcpState::Closed;
            return false;
        }
        let header_len = packet.get_data_offset() as usize * 4;
        let flags = packet.get_flags();
        if self.common.state == TcpState::SynReceived {
            if flags & ACK == ACK
                && self.common.snd_ack.0 == packet.get_sequence()
                && self.common.snd_seq.add_num(1).0 == packet.get_acknowledgement()
            {
                self.common.snd_wnd = packet.get_window();
                self.common.snd_seq = SeqNum(packet.get_acknowledgement());
                self.common.state = TcpState::Established;
                if !packet.payload().is_empty() {
                    let sequence = packet.get_sequence();
                    buf.advance(header_len);
                    self.unordered_packets.insert(SeqNum(sequence), UnreadPacket::new(flags, buf));
                }
                return true;
            }
        }
        false
    }
    pub fn is_close(&self) -> bool {
        self.common.state == TcpState::Closed
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.common.local_addr
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.common.peer_addr
    }
    pub fn split(self) -> (TcbWrite, TcbRead) {
        (TcbWrite::new(self.common), TcbRead::new(self.common, self.unordered_packets))
    }
    pub fn snd_seq(&self) -> u32 {
        self.common.snd_seq.0
    }
    pub fn snd_ack(&self) -> u32 {
        self.common.snd_ack.0
    }
    pub fn last_ack(&self) -> u32 {
        self.common.last_ack.0
    }
    pub fn snd_wnd(&self) -> u16 {
        self.common.snd_wnd
    }
    pub fn rcv_wnd(&self) -> u16 {
        self.common.rcv_wnd
    }
}

const TCP_HEAD_LEN: usize = 20;
const MAX_DIFF: u32 = u32::MAX / 2;

const MAX_PACKETS: usize = 256;

#[derive(Debug)]
struct InflightPacket {
    seq: u32,
    buf: FixedBuffer,
}

const IP_TCP_HEADER_LEN: usize = 20 + 20;

impl InflightPacket {
    pub fn new(seq: u32, buf: FixedBuffer) -> Self {
        let mut packet = Self { seq, buf };
        packet.init_reserve_head();
        packet
    }
    pub fn init_reserve_head(&mut self) {
        self.buf.clear();
        self.buf.advance(IP_TCP_HEADER_LEN);
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn advance(&mut self, cnt: usize) {
        self.seq = self.seq.wrapping_add(cnt as u32);
        self.buf.advance(cnt)
    }

    pub fn write(&mut self, buf: &[u8]) -> usize {
        self.buf.extend_from_slice(buf)
    }
    pub fn bytes(&self) -> &[u8] {
        self.buf.bytes()
    }
}

#[derive(Debug)]
pub(crate) struct TcbRead {
    common: Common,
    duplicate_ack_count: u32,
    unordered_packets: BTreeMap<SeqNum, UnreadPacket>,
}

impl TcbRead {
    fn new(common: Common, unordered_packets: BTreeMap<SeqNum, UnreadPacket>) -> Self {
        Self {
            common,
            duplicate_ack_count: 0,
            unordered_packets,
        }
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.common.local_addr
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.common.peer_addr
    }
    pub fn update_snd_seq(&mut self, snd_seq: u32) {
        self.common.snd_seq = SeqNum(snd_seq);
    }
    pub fn snd_ack(&self) -> u32 {
        self.common.snd_ack.0
    }
    pub fn snd_wnd(&self) -> u16 {
        self.common.snd_wnd
    }
    pub fn rcv_wnd(&self) -> u16 {
        self.common.rcv_wnd
    }
    pub fn last_ack(&self) -> u32 {
        self.common.last_ack.0
    }
    pub fn duplicate_ack_count(&self) -> u32 {
        self.duplicate_ack_count
    }
    pub fn push_packet(&mut self, mut buf: BytesMut) {
        let Some(packet) = TcpPacket::new(&buf) else {
            return;
        };
        let flags = packet.get_flags();
        if flags & RST == RST {
            self.common.state = TcpState::Closed;
            return;
        }
        let header_len = packet.get_data_offset() as usize * 4;
        match self.common.state {
            TcpState::Listen => {}
            TcpState::SynSent => {}
            TcpState::SynReceived => {}
            TcpState::Established => {
                if flags & ACK == ACK {
                    self.common.snd_wnd = packet.get_window();
                    let acknowledgement = SeqNum(packet.get_acknowledgement());
                    if acknowledgement == self.common.last_ack {
                        if self.common.last_ack != self.common.snd_seq {
                            self.duplicate_ack_count += 1;
                        }
                    } else if acknowledgement > self.common.last_ack {
                        self.duplicate_ack_count = 0;
                        self.common.last_ack = acknowledgement;
                    }
                }
                let sequence = SeqNum(packet.get_sequence());
                if sequence >= self.common.snd_ack {
                    buf.advance(header_len);
                    self.unordered_packets.insert(sequence, UnreadPacket::new(flags, buf));
                }
            }
            TcpState::FinWait1 => {}
            TcpState::FinWait2 => {}
            TcpState::CloseWait => {}
            TcpState::Closing => {}
            TcpState::LastAck => {}
            TcpState::TimeWait => {}
            TcpState::Closed => {}
        }
    }
    pub fn readable(&self) -> usize {
        let mut len = 0;
        for (seq, packet) in &self.unordered_packets {
            let seq = *seq;
            if self.common.snd_ack < seq {
                //unordered
                break;
            }
            let payload = &packet.payload;
            let offset = (self.common.snd_ack - seq).0 as usize;
            len += payload.len().saturating_sub(offset);
        }
        len
    }
    pub fn read(&mut self, mut buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        let len = buf.len();
        let mut fin = false;
        while let Some(v) = self.unordered_packets.first_entry() {
            let seq = *v.key();
            let packet = v.get();
            let flags = packet.flags;
            let payload = &packet.payload;
            if self.common.snd_ack < seq {
                //unordered
                break;
            }
            if flags & FIN == FIN {
                fin = true;
            }
            let offset = (self.common.snd_ack - seq).0 as usize;
            if offset >= payload.len() {
                v.remove();
                continue;
            }
            let count = payload.len() - offset;
            let min = buf.len().min(count);
            buf[..min].copy_from_slice(&payload[offset..offset + min]);
            buf = &mut buf[min..];
            self.common.snd_ack = self.common.snd_ack.add_num(min as u32);
            if min == count {
                v.remove();
            } else {
                break;
            }
        }
        if fin {
            // Processing FIN flags
            self.on_fin_received();
        }
        len - buf.len()
    }
    fn on_fin_received(&mut self) {
        match self.common.state {
            TcpState::Established => self.common.state = TcpState::CloseWait,
            TcpState::FinWait1 | TcpState::FinWait2 => self.common.state = TcpState::TimeWait,
            _ => {}
        }
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
    let mut bytes = BytesMut::with_capacity(TCP_HEAD_LEN + payload.len());
    bytes.put_u16(local_addr.port());
    bytes.put_u16(peer_addr.port());
    bytes.put_u32(snd_seq);
    bytes.put_u32(snd_ack);
    let head_len = options
        .filter(|op| !op.is_empty())
        .map(|op| {
            assert_eq!(op.len() & 3, 0, "Options must be aligned with four bytes");
            TCP_HEAD_LEN + op.len()
        })
        .unwrap_or(TCP_HEAD_LEN);
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

#[derive(Debug)]
pub struct TcbWrite {
    pub common: Common,
    back_seq: Option<SeqNum>,
    send_bufs: VecDeque<FixedBuffer>,
    inflight_packets: VecDeque<InflightPacket>,
}

impl TcbWrite {
    fn new(common: Common) -> Self {
        Self {
            common,
            back_seq: None,
            send_bufs: VecDeque::with_capacity(MAX_PACKETS),
            inflight_packets: VecDeque::with_capacity(MAX_PACKETS),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct Common {
    server: bool,
    pub(crate) local_addr: SocketAddr,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) state: TcpState,
    snd_seq: SeqNum,
    snd_ack: SeqNum,
    last_ack: SeqNum,
    snd_wnd: u16,
    rcv_wnd: u16,
    mtu: u16,
    mss: u16,
    window_shift_cnt: u8,
}

impl Common {
    fn option(&mut self, tcp_packet: &TcpPacket<'_>) {
        for tcp_option in tcp_packet.get_options_iter() {
            let payload = tcp_option.payload();
            match tcp_option.get_number() {
                TcpOptionNumbers::WSCALE => {
                    if let Some(window_shift_cnt) = payload.get(0) {
                        self.window_shift_cnt = (*window_shift_cnt).min(14);
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
    fn new_listen(local_addr: SocketAddr, peer_addr: SocketAddr, mtu: u16) -> Self {
        let snd_seq = SeqNum(rand::thread_rng().next_u32());
        Self {
            server: true,
            local_addr,
            peer_addr,
            state: TcpState::Listen,
            snd_seq,
            snd_ack: SeqNum(0),
            snd_wnd: 0,
            rcv_wnd: u16::MAX,
            last_ack: snd_seq,
            mtu,
            mss: 536,
            window_shift_cnt: 0,
        }
    }
    fn create_transport_packet(&self, flags: u8, payload: &[u8]) -> TransportPacket {
        let data = self.create_packet(flags, self.snd_seq.0, payload);
        TransportPacket::new(data, NetworkTuple::new(self.local_addr, self.peer_addr, IpNextHeaderProtocols::Tcp))
    }
    fn create_option_transport_packet(&self, flags: u8, payload: &[u8], options: Option<&[u8]>) -> TransportPacket {
        let data = self.create_option_packet(flags, self.snd_seq.0, payload, options);
        TransportPacket::new(data, NetworkTuple::new(self.local_addr, self.peer_addr, IpNextHeaderProtocols::Tcp))
    }
    fn create_transport_packet_seq(&self, flags: u8, seq: u32, payload: &[u8]) -> TransportPacket {
        let data = self.create_packet(flags, seq, payload);
        TransportPacket::new(data, NetworkTuple::new(self.local_addr, self.peer_addr, IpNextHeaderProtocols::Tcp))
    }
    fn create_packet(&self, flags: u8, seq: u32, payload: &[u8]) -> BytesMut {
        create_packet_raw(
            &self.local_addr,
            &self.peer_addr,
            seq,
            self.snd_ack.0,
            self.rcv_wnd,
            flags,
            payload,
            None,
        )
    }
    fn create_option_packet(&self, flags: u8, seq: u32, payload: &[u8], options: Option<&[u8]>) -> BytesMut {
        create_packet_raw(
            &self.local_addr,
            &self.peer_addr,
            seq,
            self.snd_ack.0,
            self.rcv_wnd,
            flags,
            payload,
            options,
        )
    }
    fn snd_seq(&self) -> u32 {
        self.snd_seq.0
    }
    fn snd_ack(&self) -> u32 {
        self.snd_ack.0
    }
    fn last_ack(&self) -> u32 {
        self.last_ack.0
    }
    fn snd_wnd(&self) -> u16 {
        self.snd_wnd
    }
    fn rcv_wnd(&self) -> u16 {
        self.rcv_wnd
    }
}

impl TcbWrite {
    pub fn snd_seq(&self) -> u32 {
        self.common.snd_seq.0
    }
    pub fn snd_ack(&self) -> u32 {
        self.common.snd_ack.0
    }
    pub fn last_ack(&self) -> u32 {
        self.common.last_ack.0
    }
    pub fn update_snd_ack(&mut self, snd_ack: u32) {
        self.common.snd_ack = SeqNum(snd_ack);
    }
    pub fn update_rcv_wnd(&mut self, rcv_wnd: u16) {
        self.common.rcv_wnd = rcv_wnd;
    }
    pub fn update_snd_wnd(&mut self, snd_wnd: u16) {
        self.common.snd_wnd = snd_wnd;
    }

    pub fn update_last_ack(&mut self, ack: u32) {
        let ack = SeqNum(ack);
        if ack <= self.common.last_ack {
            return;
        }
        let mut distance = (ack - self.common.last_ack).0 as usize;
        self.common.last_ack = ack;
        while let Some(inflight_packet) = self.inflight_packets.front_mut() {
            if inflight_packet.len() > distance {
                inflight_packet.advance(distance);
                break;
            } else {
                distance -= inflight_packet.len();
                let p = self.inflight_packets.pop_front().unwrap();
                self.send_bufs.push_back(p.buf);
            }
        }
    }
    fn send_window(&self) -> usize {
        let distance = (self.common.snd_seq - self.common.last_ack).0;
        let snd_wnd = (self.common.snd_wnd as usize) << self.common.window_shift_cnt;
        snd_wnd.saturating_sub(distance as usize)
    }
    pub fn write(&mut self, mut buf: &[u8]) -> Option<(TransportPacket, usize)> {
        let seq = self.common.snd_seq.0;
        let snd_wnd = self.send_window();
        if snd_wnd < buf.len() {
            buf = &buf[..snd_wnd];
        }
        if let Some(packet) = self.inflight_packets.back_mut() {
            let n = packet.write(&buf);
            if n > 0 {
                let packet = self.common.create_transport_packet_seq(ACK, seq, &buf[..n]);
                self.common.snd_seq = self.common.snd_seq.add_num(n as u32);
                return Some((packet, n));
            }
        }

        if let Some(mut packet) = self.take_send_buf() {
            let n = packet.write(&buf);
            self.inflight_packets.push_back(packet);
            let packet = self.common.create_transport_packet_seq(ACK, seq, &buf[..n]);
            self.common.snd_seq = self.common.snd_seq.add_num(n as u32);
            return Some((packet, n));
        }
        None
    }
    fn take_send_buf(&mut self) -> Option<InflightPacket> {
        if let Some(buf) = self.send_bufs.pop_front() {
            Some(InflightPacket::new(self.common.snd_seq.0, buf))
        } else if self.inflight_packets.len() >= MAX_PACKETS {
            None
        } else {
            let bytes_mut = FixedBuffer::with_capacity(self.common.mss as usize + IP_TCP_HEADER_LEN);
            Some(InflightPacket::new(self.common.snd_seq.0, bytes_mut))
        }
    }
    pub fn retransmission(&mut self) -> Option<TransportPacket> {
        let Some(back_seq) = self.back_seq else {
            return None;
        };
        for packet in self.inflight_packets.iter() {
            if packet.seq == back_seq.0 {
                self.back_seq.replace(back_seq.add_num(packet.len() as u32));
                return Some(self.common.create_transport_packet(ACK, packet.bytes()));
            }
        }
        self.back_seq.take();
        None
    }
    pub fn back_n(&mut self) {
        self.back_seq.replace(self.common.snd_ack);
    }
    pub fn create_transport_packet(&self, flags: u8, payload: &[u8]) -> TransportPacket {
        self.common.create_transport_packet(flags, payload)
    }
    pub fn no_inflight_packet(&self) -> bool {
        self.inflight_packets.is_empty()
    }
    pub fn inflight_packet(&self) -> usize {
        self.inflight_packets.iter().map(|v| v.buf.len()).sum()
    }
}

#[derive(Debug)]
struct UnreadPacket {
    flags: u8,
    payload: BytesMut,
}

impl UnreadPacket {
    fn new(flags: u8, payload: BytesMut) -> Self {
        Self { flags, payload }
    }
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
struct SeqNum(u32);

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
}
