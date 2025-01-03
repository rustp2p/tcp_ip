use bytes::BytesMut;
use dashmap::{DashMap, Entry};
use parking_lot::Mutex;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::Packet;
use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Notify;

pub(crate) const UNSPECIFIED_ADDR_V4: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
pub(crate) const UNSPECIFIED_ADDR_V6: SocketAddr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
pub(crate) const fn default_addr(is_v4: bool) -> SocketAddr {
    if is_v4 {
        UNSPECIFIED_ADDR_V4
    } else {
        UNSPECIFIED_ADDR_V6
    }
}
pub(crate) const fn default_ip(is_v4: bool) -> IpAddr {
    if is_v4 {
        UNSPECIFIED_ADDR_V4.ip()
    } else {
        UNSPECIFIED_ADDR_V6.ip()
    }
}
#[derive(Copy, Clone, Debug)]
pub struct IpStackConfig {
    pub mtu: u16,
    pub ip_fragment_timeout: Duration,
    pub tcp_config: crate::tcp::TcpConfig,
    pub channel_size: usize,
    pub tcp_syn_channel_size: usize,
    pub tcp_channel_size: usize,
    pub udp_channel_size: usize,
    pub icmp_channel_size: usize,
    pub ip_channel_size: usize,
}

impl IpStackConfig {
    pub fn check(&self) -> io::Result<()> {
        if self.mtu < 576 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "mtu<576"));
        }
        if self.ip_fragment_timeout.is_zero() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ip_fragment_timeout is zero"));
        }

        if self.channel_size == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "channel_size is zero"));
        }
        if self.tcp_syn_channel_size == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tcp_syn_channel_size is zero"));
        }
        if self.tcp_channel_size == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tcp_channel_size is zero"));
        }
        if self.udp_channel_size == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "udp_channel_size is zero"));
        }
        if self.icmp_channel_size == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "icmp_channel_size is zero"));
        }
        if self.ip_channel_size == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ip_channel_size is zero"));
        }
        self.tcp_config.check()
    }
}

impl Default for IpStackConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            ip_fragment_timeout: Duration::from_secs(10),
            tcp_config: Default::default(),
            channel_size: 1024,
            tcp_syn_channel_size: 128,
            tcp_channel_size: 2048,
            udp_channel_size: 1024,
            icmp_channel_size: 128,
            ip_channel_size: 128,
        }
    }
}

#[derive(Clone, Debug)]
pub struct IpStack {
    pub(crate) config: IpStackConfig,
    pub(crate) inner: Arc<IpStackInner>,
}

#[derive(Debug)]
pub(crate) struct IpStackInner {
    pub(crate) tcp_stream_map: DashMap<NetworkTuple, Sender<TransportPacket>>,
    pub(crate) tcp_listener_map: DashMap<Option<SocketAddr>, Sender<TransportPacket>>,
    pub(crate) udp_socket_map: DashMap<Option<SocketAddr>, flume::Sender<TransportPacket>>,
    pub(crate) raw_socket_map: DashMap<(Option<IpNextHeaderProtocol>, Option<SocketAddr>), flume::Sender<TransportPacket>>,
    pub(crate) packet_sender: Sender<TransportPacket>,
}

pub struct IpStackSend {
    ip_stack: IpStack,
    ident_fragments_map: Arc<Mutex<HashMap<IdKey, IpFragments>>>,
    notify: Arc<Notify>,
}

impl Drop for IpStackSend {
    fn drop(&mut self) {
        self.notify.notify_one();
    }
}

impl IpStackSend {
    pub(crate) fn new(ip_stack: IpStack) -> Self {
        Self {
            ip_stack,
            ident_fragments_map: Default::default(),
            notify: Arc::new(Notify::new()),
        }
    }
}

pub struct IpStackRecv {
    inner: IpStackRecvInner,
    index: usize,
    num: usize,
    sizes: Vec<usize>,
    bufs: Vec<BytesMut>,
}
struct IpStackRecvInner {
    ip_stack: IpStack,
    identification: u16,
    packet_receiver: Receiver<TransportPacket>,
}

impl IpStackRecv {
    pub(crate) fn new(ip_stack: IpStack, packet_receiver: Receiver<TransportPacket>) -> Self {
        let identification = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|v| (v.as_millis() & 0xFFFF) as u16)
            .unwrap_or(0);
        let inner = IpStackRecvInner {
            ip_stack,
            identification,
            packet_receiver,
        };
        Self {
            inner,
            index: 0,
            num: 0,
            sizes: Vec::new(),
            bufs: Vec::new(),
        }
    }
}

#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy)]
pub(crate) struct NetworkTuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: IpNextHeaderProtocol,
}

impl NetworkTuple {
    pub fn new(src: SocketAddr, dst: SocketAddr, protocol: IpNextHeaderProtocol) -> Self {
        assert_eq!(src.is_ipv4(), dst.is_ipv4());
        Self { src, dst, protocol }
    }
    pub fn is_ipv4(&self) -> bool {
        self.src.is_ipv4()
    }
}

#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy)]
struct IdKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: IpNextHeaderProtocol,
    pub identification: u16,
}

impl IdKey {
    fn new(src: IpAddr, dst: IpAddr, protocol: IpNextHeaderProtocol, identification: u16) -> Self {
        Self {
            src,
            dst,
            protocol,
            identification,
        }
    }
}

/// Create a user-space protocol stack.
///
/// # Examples
/// ```rust
/// use tcp_ip::tcp::TcpListener;
/// async fn main(){
///     let (ip_stack, ip_stack_send, ip_stack_recv) = tcp_ip::ip_stack(Default::default())?;
///     // Use ip_stack_send and ip_stack_recv to interface
///     // with the input and output of IP packets.
///     // ...
///     let mut tcp_listener = TcpListener::bind_all(ip_stack.clone()).await?;
/// }
/// ```
pub fn ip_stack(config: IpStackConfig) -> io::Result<(IpStack, IpStackSend, IpStackRecv)> {
    config.check()?;
    let (packet_sender, packet_receiver) = channel(config.channel_size);
    let ip_stack = IpStack::new(config, packet_sender);
    let ip_stack_send = IpStackSend::new(ip_stack.clone());
    let ip_stack_recv = IpStackRecv::new(ip_stack.clone(), packet_receiver);
    {
        let ident_fragments_map = ip_stack_send.ident_fragments_map.clone();
        let notify = ip_stack_send.notify.clone();
        let timeout = ip_stack.config.ip_fragment_timeout;
        tokio::spawn(async move {
            loop_check_timeouts(timeout, ident_fragments_map, notify).await;
        });
    }
    Ok((ip_stack, ip_stack_send, ip_stack_recv))
}

async fn loop_check_timeouts(timeout: Duration, ident_fragments_map: Arc<Mutex<HashMap<IdKey, IpFragments>>>, notify: Arc<Notify>) {
    let notified = notify.notified();
    tokio::pin!(notified);
    loop {
        tokio::select! {
            _=&mut notified=>{
                break;
            }
            _=tokio::time::sleep(timeout)=>{
                check_timeouts(&ident_fragments_map,timeout);
            }

        }
    }
}

fn check_timeouts(ident_fragments_map: &Mutex<HashMap<IdKey, IpFragments>>, timeout: Duration) {
    if let Some(mut ident_fragments_map) = ident_fragments_map.try_lock() {
        let now = Instant::now();
        // Clear timeout IP segmentation
        ident_fragments_map.retain(|_id_key, p| p.time + timeout > now)
    }
}

impl IpStack {
    pub(crate) fn new(config: IpStackConfig, packet_sender: Sender<TransportPacket>) -> Self {
        Self {
            config,
            inner: Arc::new(IpStackInner {
                tcp_stream_map: Default::default(),
                tcp_listener_map: Default::default(),
                udp_socket_map: Default::default(),
                raw_socket_map: Default::default(),
                packet_sender,
            }),
        }
    }
    pub(crate) fn add_socket(
        &self,
        protocol: Option<IpNextHeaderProtocol>,
        local_addr: Option<SocketAddr>,
        packet_sender: flume::Sender<TransportPacket>,
    ) -> io::Result<()> {
        match protocol {
            Some(IpNextHeaderProtocols::Udp) => Self::add_socket0(&self.inner.udp_socket_map, local_addr, packet_sender),
            protocol => Self::add_socket0(&self.inner.raw_socket_map, (protocol, local_addr), packet_sender),
        }
    }
    pub(crate) fn add_tcp_listener(&self, local_addr: Option<SocketAddr>, packet_sender: Sender<TransportPacket>) -> io::Result<()> {
        Self::add_socket0(&self.inner.tcp_listener_map, local_addr, packet_sender)
    }
    pub(crate) fn remove_tcp_listener(&self, local_addr: &Option<SocketAddr>) {
        self.inner.tcp_listener_map.remove(local_addr);
    }
    pub(crate) fn add_tcp_socket(&self, network_tuple: NetworkTuple, packet_sender: Sender<TransportPacket>) -> io::Result<()> {
        Self::add_socket0(&self.inner.tcp_stream_map, network_tuple, packet_sender)
    }
    pub(crate) fn remove_tcp_socket(&self, network_tuple: &NetworkTuple) {
        self.inner.tcp_stream_map.remove(network_tuple);
    }
    pub(crate) fn remove_socket(&self, protocol: Option<IpNextHeaderProtocol>, local_addr: &Option<SocketAddr>) {
        match protocol {
            Some(IpNextHeaderProtocols::Udp) => {
                self.inner.udp_socket_map.remove(local_addr);
            }
            protocol => {
                self.inner.raw_socket_map.remove(&(protocol, *local_addr));
            }
        }
    }
    fn add_socket0<K: Eq + PartialEq + Hash, V>(map: &DashMap<K, V>, local_addr: K, packet_sender: V) -> io::Result<()> {
        let entry = map.entry(local_addr);
        match entry {
            Entry::Occupied(_entry) => Err(io::Error::from(io::ErrorKind::AddrNotAvailable)),
            Entry::Vacant(entry) => {
                entry.insert(packet_sender);
                Ok(())
            }
        }
    }
    pub(crate) async fn send_packet(&self, transport_packet: TransportPacket) -> io::Result<()> {
        match self.inner.packet_sender.send(transport_packet).await {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::new(io::ErrorKind::WriteZero, "ip stack close")),
        }
    }
}

impl IpStackSend {
    /// Send the IP packet to this protocol stack.
    pub async fn send_ip_packet(&mut self, buf: &[u8]) -> io::Result<()> {
        let p = buf[0] >> 4;
        match p {
            4 => {
                let Some(packet) = Ipv4Packet::new(buf) else {
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                };

                let id_key = convert_id_key(&packet);

                let Some(network_tuple) = self.prepare_ipv4_fragments(&packet, id_key)? else {
                    return Ok(());
                };
                let mut sender = match packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => self.get_tcp_sender(&network_tuple),
                    IpNextHeaderProtocols::Udp => self.get_udp_sender(&network_tuple),
                    _ => None,
                };
                if sender.is_none() {
                    sender = self.get_raw_sender(packet.get_next_level_protocol(), &network_tuple);
                }
                if let Some(sender) = sender {
                    let rs = self.transmit_ip_packet(sender, packet, id_key, network_tuple).await;
                    if rs.is_err() {
                        self.clear_fragment_cache(&id_key);
                    }
                    rs
                } else {
                    self.clear_fragment_cache(&id_key);
                    Ok(())
                }
            }
            6 => {
                let Some(packet) = Ipv6Packet::new(buf) else {
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                };
                // todo Need to handle fragmentation, routing, and other header information.
                let network_tuple = self.prepare_ipv6_fragments(&packet)?;
                let mut sender = match packet.get_next_header() {
                    IpNextHeaderProtocols::Tcp => self.get_tcp_sender(&network_tuple),
                    IpNextHeaderProtocols::Udp => self.get_udp_sender(&network_tuple),
                    _ => None,
                };
                if sender.is_none() {
                    sender = self.get_raw_sender(packet.get_next_header(), &network_tuple);
                }
                if let Some(sender) = sender {
                    _ = sender.send(TransportPacket::new(packet.payload().into(), network_tuple)).await;
                }
                Ok(())
            }
            _ => Err(io::Error::from(io::ErrorKind::InvalidInput)),
        }
    }
    fn get_tcp_sender(&mut self, network_tuple: &NetworkTuple) -> Option<SenderBox<TransportPacket>> {
        let stack = &self.ip_stack.inner;
        if let Some(tcp) = stack.tcp_stream_map.get(network_tuple) {
            Some(SenderBox::Mpsc(tcp.value().clone()))
        } else if let Some(tcp) = stack.tcp_listener_map.get(&Some(network_tuple.dst)) {
            Some(SenderBox::Mpsc(tcp.value().clone()))
        } else {
            let dst = SocketAddr::new(default_ip(network_tuple.is_ipv4()), network_tuple.dst.port());
            if let Some(tcp) = stack.tcp_listener_map.get(&Some(dst)) {
                Some(SenderBox::Mpsc(tcp.value().clone()))
            } else if let Some(tcp) = stack.tcp_listener_map.get(&Some(default_addr(network_tuple.is_ipv4()))) {
                Some(SenderBox::Mpsc(tcp.value().clone()))
            } else {
                stack.tcp_listener_map.get(&None).map(|tcp| SenderBox::Mpsc(tcp.value().clone()))
            }
        }
    }
    fn get_udp_sender(&mut self, network_tuple: &NetworkTuple) -> Option<SenderBox<TransportPacket>> {
        let stack = &self.ip_stack.inner;
        if let Some(udp) = stack.udp_socket_map.get(&Some(network_tuple.dst)) {
            Some(SenderBox::Mpmc(udp.value().clone()))
        } else {
            let dst = SocketAddr::new(default_ip(network_tuple.is_ipv4()), network_tuple.dst.port());
            if let Some(udp) = stack.udp_socket_map.get(&Some(dst)) {
                Some(SenderBox::Mpmc(udp.value().clone()))
            } else if let Some(udp) = stack.udp_socket_map.get(&Some(default_addr(network_tuple.is_ipv4()))) {
                Some(SenderBox::Mpmc(udp.value().clone()))
            } else {
                stack.udp_socket_map.get(&None).map(|udp| SenderBox::Mpmc(udp.value().clone()))
            }
        }
    }
    fn get_raw_sender(&mut self, protocol: IpNextHeaderProtocol, network_tuple: &NetworkTuple) -> Option<SenderBox<TransportPacket>> {
        if let Some(v) = self.get_raw_sender0(Some(protocol), network_tuple) {
            Some(v)
        } else {
            self.get_raw_sender0(None, network_tuple)
        }
    }
    fn get_raw_sender0(
        &mut self,
        protocol: Option<IpNextHeaderProtocol>,
        network_tuple: &NetworkTuple,
    ) -> Option<SenderBox<TransportPacket>> {
        let stack = &self.ip_stack.inner;
        if let Some(socket) = stack.raw_socket_map.get(&(protocol, Some(network_tuple.dst))) {
            Some(SenderBox::Mpmc(socket.value().clone()))
        } else {
            let dst = SocketAddr::new(default_ip(network_tuple.is_ipv4()), network_tuple.dst.port());
            if let Some(socket) = stack.raw_socket_map.get(&(protocol, Some(dst))) {
                Some(SenderBox::Mpmc(socket.value().clone()))
            } else if let Some(socket) = stack.raw_socket_map.get(&(protocol, Some(default_addr(network_tuple.is_ipv4())))) {
                Some(SenderBox::Mpmc(socket.value().clone()))
            } else {
                stack
                    .raw_socket_map
                    .get(&(protocol, None))
                    .map(|icmp| SenderBox::Mpmc(icmp.value().clone()))
            }
        }
    }
    async fn transmit_ip_packet(
        &mut self,
        sender: SenderBox<TransportPacket>,
        packet: Ipv4Packet<'_>,
        id_key: IdKey,
        network_tuple: NetworkTuple,
    ) -> io::Result<()> {
        let more_fragments = packet.get_flags() & Ipv4Flags::MoreFragments == Ipv4Flags::MoreFragments;
        let offset = packet.get_fragment_offset();
        let segmented = more_fragments || offset > 0;
        let buf = if segmented {
            // merge ip fragments
            if let Some(buf) = self.merge_ip_fragments(&packet, id_key, network_tuple)? {
                buf
            } else {
                // Need to wait for all shards to arrive
                return Ok(());
            }
        } else {
            // confirm that the id is not occupied
            self.clear_fragment_cache(&id_key);
            packet.payload().into()
        };
        _ = sender.send(TransportPacket::new(buf, network_tuple)).await;
        Ok(())
    }
    fn prepare_ipv4_fragments(&mut self, ip_packet: &Ipv4Packet<'_>, id_key: IdKey) -> io::Result<Option<NetworkTuple>> {
        let offset = ip_packet.get_fragment_offset();
        let network_tuple = if offset == 0
            || (ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp
                && ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp)
        {
            // No segmentation or the first segmentation
            convert_network_tuple(ip_packet)?
        } else {
            let mut guard = self.ident_fragments_map.lock();
            let p = guard.entry(id_key).or_default();

            if let Some(v) = p.network_tuple {
                v
            } else {
                // Perhaps the first IP segment has not yet arrived,
                // so the network tuple cannot be obtained.
                let last_fragment = ip_packet.get_flags() & Ipv4Flags::MoreFragments != Ipv4Flags::MoreFragments;
                p.add_fragment(ip_packet.into(), last_fragment)?;
                return Ok(None);
            }
        };
        Ok(Some(network_tuple))
    }
    fn prepare_ipv6_fragments(&mut self, ip_packet: &Ipv6Packet<'_>) -> io::Result<NetworkTuple> {
        match ip_packet.get_next_header() {
            IpNextHeaderProtocols::Ipv6Frag
            | IpNextHeaderProtocols::Ipv6Route
            | IpNextHeaderProtocols::Ipv6Opts
            | IpNextHeaderProtocols::Ipv6NoNxt => {
                // todo Handle IP fragmentation.
                return Err(Error::new(io::ErrorKind::Unsupported, "ipv6 option"));
            }
            _ => {}
        }
        convert_network_tuple_v6(ip_packet)
    }
    fn merge_ip_fragments(
        &mut self,
        ip_packet: &Ipv4Packet<'_>,
        id_key: IdKey,
        network_tuple: NetworkTuple,
    ) -> io::Result<Option<BytesMut>> {
        let mut map = self.ident_fragments_map.lock();
        let ip_fragments = map
            .entry(id_key)
            .and_modify(|p| p.update_time())
            .or_insert_with(|| IpFragments::new(network_tuple));

        let last_fragment = ip_packet.get_flags() & Ipv4Flags::MoreFragments != Ipv4Flags::MoreFragments;
        let offset = ip_packet.get_fragment_offset() << 3;
        if last_fragment {
            ip_fragments.last_offset.replace(offset);
        }
        ip_fragments.add_fragment(ip_packet.into(), last_fragment)?;

        if ip_fragments.is_complete() {
            //This place cannot be None
            let mut fragments = map.remove(&id_key).unwrap();
            fragments
                .bufs
                .sort_by(|ip_fragment1, ip_fragment2| ip_fragment1.offset.cmp(&ip_fragment2.offset));
            let mut total_payload_len = 0;
            for ip_fragment in &fragments.bufs {
                if total_payload_len as u16 != ip_fragment.offset {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("fragment offset error:{total_payload_len}!={}", ip_fragment.offset),
                    ));
                }
                total_payload_len += ip_fragment.payload.len();
            }
            let mut p = BytesMut::with_capacity(total_payload_len);
            for ip_fragment in &fragments.bufs {
                p.extend_from_slice(&ip_fragment.payload);
            }
            return Ok(Some(p));
        }

        Ok(None)
    }
    fn clear_fragment_cache(&self, id_key: &IdKey) {
        let mut guard = self.ident_fragments_map.lock();
        guard.remove(id_key);
    }
}

impl IpStackRecv {
    /// Read a single IP packet from the protocol stack.
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.num > self.index {
                let index = self.index;
                let len = self.sizes[index];
                if buf.len() < len {
                    return Err(Error::new(io::ErrorKind::InvalidInput, "bufs too short"));
                }
                buf[..len].copy_from_slice(&self.bufs[index][..len]);
                self.index += 1;
                return Ok(len);
            }
            self.index = 0;
            self.num = 0;
            if self.sizes.is_empty() {
                self.sizes.resize(128, 0);
            }
            if self.bufs.is_empty() {
                for _ in 0..128 {
                    self.bufs.push(BytesMut::zeroed(self.inner.ip_stack.config.mtu as usize));
                }
            }
            self.num = self.inner.recv_ip_packet(&mut self.bufs, &mut self.sizes).await?;
            if self.num == 0 {
                return Err(Error::new(io::ErrorKind::UnexpectedEof, "read 0"));
            }
        }
    }
    /// Read multiple IP packets from the protocol stack at once.
    pub async fn recv_ip_packet<B: AsMut<[u8]>>(&mut self, bufs: &mut [B], sizes: &mut [usize]) -> io::Result<usize> {
        self.inner.recv_ip_packet(bufs, sizes).await
    }
}
impl IpStackRecvInner {
    async fn recv_ip_packet<B: AsMut<[u8]>>(&mut self, bufs: &mut [B], sizes: &mut [usize]) -> io::Result<usize> {
        if bufs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bufs is empty"));
        }
        if bufs.len() != sizes.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bufs.len!=sizes.len"));
        }
        if let Some(packet) = self.packet_receiver.recv().await {
            match (packet.network_tuple.src.is_ipv6(), packet.network_tuple.dst.is_ipv6()) {
                (true, true) => self.wrap_in_ipv6(bufs, sizes, packet),
                (false, false) => self.split_ip_packet(bufs, sizes, packet),
                (_, _) => Err(io::Error::new(io::ErrorKind::InvalidInput, "address error")),
            }
        } else {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "close"))
        }
    }
    fn wrap_in_ipv6<B: AsMut<[u8]>>(&mut self, bufs: &mut [B], sizes: &mut [usize], packet: TransportPacket) -> io::Result<usize> {
        let buf = bufs[0].as_mut();
        let total_length = 40 + packet.buf.len();
        if buf.len() < total_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bufs[0] too short.{total_length}>{:?}", buf.len()),
            ));
        }
        let src_ip = match packet.network_tuple.src.ip() {
            IpAddr::V6(ip) => ip,
            IpAddr::V4(_) => unimplemented!(),
        };
        let dst_ip = match packet.network_tuple.dst.ip() {
            IpAddr::V6(ip) => ip,
            IpAddr::V4(_) => unimplemented!(),
        };
        // 创建一个可变的IPv6数据包
        let Some(mut ipv6_packet) = pnet_packet::ipv6::MutableIpv6Packet::new(&mut buf[..total_length]) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "ipv6 data error"));
        };
        ipv6_packet.set_version(6);
        ipv6_packet.set_traffic_class(0);
        ipv6_packet.set_flow_label(0);
        ipv6_packet.set_payload_length(packet.buf.len() as u16); // 设置负载长度
        ipv6_packet.set_next_header(packet.network_tuple.protocol);
        ipv6_packet.set_hop_limit(64);
        ipv6_packet.set_source(src_ip);
        ipv6_packet.set_destination(dst_ip);
        // 添加负载数据
        ipv6_packet.set_payload(&packet.buf);
        sizes[0] = total_length;
        Ok(1)
    }
    fn split_ip_packet<B: AsMut<[u8]>>(&mut self, bufs: &mut [B], sizes: &mut [usize], packet: TransportPacket) -> io::Result<usize> {
        let mtu = self.ip_stack.config.mtu;
        self.identification = self.identification.wrapping_sub(1);
        let identification = self.identification;
        let mut offset = 0;
        let mut total_packets = 0;

        const IPV4_HEADER_SIZE: usize = 20; // IPv4 header fixed size
        let max_payload_size = mtu as usize - IPV4_HEADER_SIZE;
        let max_payload_size_8 = max_payload_size & !0b111;
        let src_ip = match packet.network_tuple.src.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => unimplemented!(),
        };
        let dst_ip = match packet.network_tuple.dst.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => unimplemented!(),
        };
        let protocol = packet.network_tuple.protocol.0;

        while offset < packet.buf.len() {
            let remaining = packet.buf.len() - offset;
            let fragment_size = if remaining > max_payload_size {
                max_payload_size_8
            } else {
                remaining
            };
            let total_length = IPV4_HEADER_SIZE + fragment_size;
            if total_packets >= bufs.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "bufs too short"));
            }
            let buf = bufs[total_packets].as_mut();
            if total_length > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("bufs[{total_packets}] too short.{total_length}>{:?}", buf.len()),
                ));
            }
            let more_fragments = if remaining > fragment_size { 1 } else { 0 };
            assert_eq!(offset & 0b111, 0, "Offset must be a multiple of 8");
            let fragment_offset = ((offset & !0b111) as u16) >> 3;
            let flags_fragment_offset = (more_fragments << 13) | fragment_offset;

            let ip_header = &mut buf[..IPV4_HEADER_SIZE];
            ip_header[0] = (4 << 4) | (IPV4_HEADER_SIZE / 4) as u8; // Version (4) + IHL
            ip_header[1] = 0; // Type of Service
            ip_header[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
            ip_header[4..6].copy_from_slice(&identification.to_be_bytes());
            ip_header[6..8].copy_from_slice(&flags_fragment_offset.to_be_bytes());
            ip_header[8] = 64; // TTL
            ip_header[9] = protocol;
            ip_header[12..16].copy_from_slice(&src_ip.octets());
            ip_header[16..20].copy_from_slice(&dst_ip.octets());

            let checksum = pnet_packet::util::checksum(ip_header, 5);
            ip_header[10..12].copy_from_slice(&checksum.to_be_bytes());
            let ip_payload = &mut buf[IPV4_HEADER_SIZE..total_length];
            ip_payload.copy_from_slice(&packet.buf[offset..offset + fragment_size]);
            offset += fragment_size;
            sizes[total_packets] = total_length;
            total_packets += 1;
        }
        Ok(total_packets)
    }
}

#[derive(Debug)]
pub(crate) struct TransportPacket {
    pub buf: BytesMut,
    pub network_tuple: NetworkTuple,
}

impl TransportPacket {
    pub fn new(buf: BytesMut, network_tuple: NetworkTuple) -> Self {
        Self { buf, network_tuple }
    }
}

struct IpFragments {
    network_tuple: Option<NetworkTuple>,
    bufs: Vec<IpFragment>,
    // Read IP payload length(Excluding the last IP segment).
    read_len: u16,
    // The offset of the last segment.
    // If last_offset == read_len, it means all fragments have been received.
    last_offset: Option<u16>,
    time: Instant,
}

struct IpFragment {
    offset: u16,
    payload: BytesMut,
}

impl From<&Ipv4Packet<'_>> for IpFragment {
    fn from(value: &Ipv4Packet<'_>) -> Self {
        Self {
            offset: value.get_fragment_offset() << 3,
            payload: value.payload().into(),
        }
    }
}

impl Default for IpFragments {
    fn default() -> Self {
        Self {
            network_tuple: None,
            bufs: Vec::with_capacity(8),
            read_len: 0,
            last_offset: None,
            time: Instant::now(),
        }
    }
}

impl IpFragments {
    fn new(network_tuple: NetworkTuple) -> Self {
        Self {
            network_tuple: Some(network_tuple),
            ..Self::default()
        }
    }
    fn update_time(&mut self) {
        self.time = Instant::now();
    }
    fn add_fragment(&mut self, ip_fragment: IpFragment, last_fragment: bool) -> io::Result<()> {
        if !last_fragment {
            let (read_len, overflow) = self.read_len.overflowing_add(ip_fragment.payload.len() as u16);
            if overflow {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "IP segment length overflow"));
            }
            self.read_len = read_len;
        }

        self.bufs.push(ip_fragment);
        Ok(())
    }
    fn is_complete(&self) -> bool {
        if let Some(last_offset) = self.last_offset {
            last_offset == self.read_len
        } else {
            false
        }
    }
}

fn convert_network_tuple(packet: &Ipv4Packet) -> io::Result<NetworkTuple> {
    let src_ip = packet.get_source();
    let dest_ip = packet.get_destination();
    let (src_port, dest_port) = match packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let Some(tcp_packet) = pnet_packet::tcp::TcpPacket::new(packet.payload()) else {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            };
            (tcp_packet.get_source(), tcp_packet.get_destination())
        }
        IpNextHeaderProtocols::Udp => {
            let Some(udp_packet) = pnet_packet::udp::UdpPacket::new(packet.payload()) else {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            };
            (udp_packet.get_source(), udp_packet.get_destination())
        }
        _ => (0, 0),
    };

    let src_addr = SocketAddrV4::new(src_ip, src_port);
    let dest_addr = SocketAddrV4::new(dest_ip, dest_port);
    let protocol = packet.get_next_level_protocol();
    let network_tuple = NetworkTuple::new(src_addr.into(), dest_addr.into(), protocol);
    Ok(network_tuple)
}
fn convert_network_tuple_v6(packet: &Ipv6Packet) -> io::Result<NetworkTuple> {
    let src_ip = packet.get_source();
    let dest_ip = packet.get_destination();
    let protocol = packet.get_next_header();

    let (src_port, dest_port) = match protocol {
        IpNextHeaderProtocols::Tcp => {
            let Some(tcp_packet) = pnet_packet::tcp::TcpPacket::new(packet.payload()) else {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            };
            (tcp_packet.get_source(), tcp_packet.get_destination())
        }
        IpNextHeaderProtocols::Udp => {
            let Some(udp_packet) = pnet_packet::udp::UdpPacket::new(packet.payload()) else {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            };
            (udp_packet.get_source(), udp_packet.get_destination())
        }
        _ => (0, 0),
    };

    let src_addr = SocketAddrV6::new(src_ip, src_port, 0, 0);
    let dest_addr = SocketAddrV6::new(dest_ip, dest_port, 0, 0);
    let network_tuple = NetworkTuple::new(src_addr.into(), dest_addr.into(), protocol);
    Ok(network_tuple)
}

fn convert_id_key(packet: &Ipv4Packet) -> IdKey {
    let src_ip = packet.get_source();
    let dest_ip = packet.get_destination();
    let protocol = packet.get_next_level_protocol();
    let identification = packet.get_identification();
    IdKey::new(src_ip.into(), dest_ip.into(), protocol, identification)
}

enum SenderBox<T> {
    Mpsc(Sender<T>),
    Mpmc(flume::Sender<T>),
}

impl<T> SenderBox<T> {
    async fn send(&self, t: T) -> bool {
        match self {
            SenderBox::Mpsc(sender) => sender.send(t).await.is_ok(),
            SenderBox::Mpmc(sender) => sender.send_async(t).await.is_ok(),
        }
    }
}
