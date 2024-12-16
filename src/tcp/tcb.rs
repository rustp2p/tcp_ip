use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::ops::{Add, Sub};

use bytes::{Buf, BufMut, BytesMut};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::TcpFlags::{ACK, FIN, PSH, RST};
use pnet_packet::tcp::TcpPacket;
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
    pub fn new_syn_received(
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        seq: u32,
        wnd: u16,
        mtu: u16,
    ) -> Self {
        let common = Common::new_syn_received(local_addr, peer_addr, seq, wnd, mtu);
        Self {
            common,
            unordered_packets: Default::default(),
        }
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
                    self.unordered_packets
                        .insert(SeqNum(sequence), UnreadPacket::new(flags, buf));
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
        (
            TcbWrite::new(self.common),
            TcbRead::new(self.common, self.unordered_packets),
        )
    }
    pub fn create_transport_packet(&self, flags: u8, payload: &[u8]) -> TransportPacket {
        self.common.create_transport_packet(flags, payload)
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

const MAX_PACKETS: usize = 64;

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
                    self.unordered_packets
                        .insert(sequence, UnreadPacket::new(flags, buf));
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
                log::error!("unordered {seq:?},ack={:?}",self.common.snd_ack);
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
    let data = create_packet_raw(
        local_addr, peer_addr, snd_seq, rcv_ack, rcv_wnd, flags, payload,
    );
    TransportPacket::new(
        data,
        NetworkTuple::new(*local_addr, *peer_addr, IpNextHeaderProtocols::Tcp),
    )
}

pub fn create_packet_raw(
    local_addr: &SocketAddr,
    peer_addr: &SocketAddr,
    snd_seq: u32,
    snd_ack: u32,
    rcv_wnd: u16,
    flags: u8,
    payload: &[u8],
) -> BytesMut {
    let mut bytes = BytesMut::with_capacity(TCP_HEAD_LEN + payload.len());
    bytes.put_u16(local_addr.port());
    bytes.put_u16(peer_addr.port());
    bytes.put_u32(snd_seq);
    bytes.put_u32(snd_ack);
    // Data Offset
    bytes.put_u8((TCP_HEAD_LEN as u8 / 4) << 4);
    bytes.put_u8(flags);
    bytes.put_u16(rcv_wnd);
    // Checksum
    bytes.put_u16(0);
    // Urgent Pointer
    bytes.put_u16(0);
    bytes.extend_from_slice(payload);
    let checksum = match (local_addr.ip(), peer_addr.ip()) {
        (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => pnet_packet::util::ipv4_checksum(
            &bytes,
            8,
            &[],
            &src_ip,
            &dst_ip,
            IpNextHeaderProtocols::Tcp,
        ),
        (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => pnet_packet::util::ipv6_checksum(
            &bytes,
            8,
            &[],
            &src_ip,
            &dst_ip,
            IpNextHeaderProtocols::Tcp,
        ),
        (_, _) => {
            unreachable!()
        }
    };
    bytes[16..18].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

#[derive(Debug)]
pub struct TcbWrite {
    common: Common,
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
struct Common {
    server: bool,
    pub(crate) local_addr: SocketAddr,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) state: TcpState,
    snd_seq: SeqNum,
    snd_ack: SeqNum,
    last_ack: SeqNum,
    snd_wnd: u16,
    rcv_wnd: u16,
    mtu: usize,
}

impl Common {
    fn new_syn_received(
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        seq: u32,
        wnd: u16,
        mtu: u16,
    ) -> Self {
        let snd_seq = SeqNum(rand::thread_rng().next_u32());
        Self {
            server: true,
            local_addr,
            peer_addr,
            state: TcpState::SynReceived,
            snd_seq,
            snd_ack: SeqNum(seq).add_num(1),
            snd_wnd: wnd,
            rcv_wnd: u16::MAX,
            last_ack: snd_seq,
            mtu: mtu as usize,
        }
    }
    fn create_transport_packet(&self, flags: u8, payload: &[u8]) -> TransportPacket {
        let data = self.create_packet(flags, self.snd_seq.0, payload);
        TransportPacket::new(
            data,
            NetworkTuple::new(self.local_addr, self.peer_addr, IpNextHeaderProtocols::Tcp),
        )
    }
    fn create_transport_packet_seq(&self, flags: u8, seq: u32, payload: &[u8]) -> TransportPacket {
        let data = self.create_packet(flags, seq, payload);
        TransportPacket::new(
            data,
            NetworkTuple::new(self.local_addr, self.peer_addr, IpNextHeaderProtocols::Tcp),
        )
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

    pub fn update_last_ack(&mut self, ack: u32) {
        let ack = SeqNum(ack);
        if ack <= self.common.last_ack {
            return;
        }

        let mut distance = (ack - self.common.last_ack).0 as usize;
        self.common.last_ack = ack;
        while let Some(inflight_packet) = self.inflight_packets.back_mut() {
            if inflight_packet.len() > distance {
                inflight_packet.advance(distance);
                break;
            } else {
                distance -= inflight_packet.len();
                let p = self.inflight_packets.pop_back().unwrap();
                self.send_bufs.push_back(p.buf);
            }
        }
    }
    pub fn write(&mut self, buf: &[u8]) -> Option<(TransportPacket, usize)> {
        let mut offset = 0;
        let seq = self.common.snd_seq.0;
        if let Some(packet) = self.inflight_packets.front_mut() {
            let n = packet.write(&buf[offset..]);
            self.common.snd_seq = self.common.snd_seq.add_num(n as u32);
            offset += n;
        }
        if offset != buf.len() {
            while let Some(mut packet) = self.take_send_buf() {
                let n = packet.write(&buf[offset..]);
                self.inflight_packets.push_front(packet);
                self.common.snd_seq = self.common.snd_seq.add_num(n as u32);
                offset += n;
                if offset == buf.len() {
                    break;
                }
            }
        }
        if offset == 0 {
            return None;
        }
        let packet = self
            .common
            .create_transport_packet_seq(PSH | ACK, seq, &buf[..offset]);
        Some((packet, offset))
    }
    fn take_send_buf(&mut self) -> Option<InflightPacket> {
        if let Some(buf) = self.send_bufs.pop_front() {
            Some(InflightPacket::new(self.common.snd_seq.0, buf))
        } else if self.inflight_packets.len() >= MAX_PACKETS {
            None
        } else {
            let bytes_mut = FixedBuffer::with_capacity(self.common.mtu);
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
                return Some(
                    self.common
                        .create_transport_packet(PSH | ACK, packet.bytes()),
                );
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
        let a = self.0;
        let b = other.0;
        let diff = a.wrapping_sub(b);
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
