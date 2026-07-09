use bytes::{Bytes, BytesMut};
use dashmap::{DashMap, DashSet, Entry};
use parking_lot::Mutex;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::Packet;
use pnet_packet::{tcp::TcpPacket, udp::UdpPacket};
use rand::RngExt;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Notify;

pub(crate) const UNSPECIFIED_ADDR_V4: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
pub(crate) const UNSPECIFIED_ADDR_V6: SocketAddr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
const MAX_FRAGMENT_ENTRIES: usize = 128;
const MAX_FRAGMENTS_PER_PACKET: usize = 128;
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
pub(crate) fn validate_addr(dest: SocketAddr) -> io::Result<()> {
    if dest.port() == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid port"));
    }
    validate_ip(dest.ip())?;
    Ok(())
}
pub(crate) fn validate_ip(ip: IpAddr) -> io::Result<()> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("IP is unspecified: {}", ip)));
            }
            if v4.is_multicast() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("IP is multicast: {}", ip)));
            }
            if v4.is_broadcast() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("IP is broadcast: {}", ip)));
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("IP is unspecified: {}", ip)));
            }
            if v6.is_multicast() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("IP is multicast: {}", ip)));
            }
        }
    }
    Ok(())
}
pub(crate) fn check_addr(addr: SocketAddr) -> io::Result<()> {
    if addr.port() == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid port"));
    }
    check_ip(addr.ip())
}
pub(crate) fn check_ip(ip: IpAddr) -> io::Result<()> {
    if match ip {
        IpAddr::V4(ip) => ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_unspecified(),
    } {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid ip"))
    } else {
        Ok(())
    }
}
/// Configure the protocol stack
#[derive(Copy, Clone, Debug)]
pub struct IpStackConfig {
    ipv4_mtu: u16,
    ipv6_mtu: u16,
    ip_fragment_timeout: Duration,
    validate_checksums: bool,
    tcp_max_half_open: usize,
    tcp_config: crate::tcp::TcpConfig,
    channel_size: usize,
    tcp_syn_channel_size: usize,
    tcp_channel_size: usize,
    udp_channel_size: usize,
    icmp_channel_size: usize,
    ip_channel_size: usize,
}

impl IpStackConfig {
    pub const IPV4_MIN_MTU: u16 = 576;
    pub const IPV6_MIN_MTU: u16 = 1280;

    pub fn builder() -> IpStackConfigBuilder {
        IpStackConfigBuilder::default()
    }

    pub fn ipv4_mtu(&self) -> u16 {
        self.ipv4_mtu
    }

    pub fn ipv6_mtu(&self) -> u16 {
        self.ipv6_mtu
    }

    pub fn mtu_for_ip(&self, is_ipv4: bool) -> u16 {
        if is_ipv4 {
            self.ipv4_mtu
        } else {
            self.ipv6_mtu
        }
    }

    pub fn ip_fragment_timeout(&self) -> Duration {
        self.ip_fragment_timeout
    }

    pub fn validate_checksums(&self) -> bool {
        self.validate_checksums
    }

    pub fn tcp_max_half_open(&self) -> usize {
        self.tcp_max_half_open
    }

    pub fn tcp_config(&self) -> crate::tcp::TcpConfig {
        self.tcp_config
    }

    pub fn channel_size(&self) -> usize {
        self.channel_size
    }

    pub fn tcp_syn_channel_size(&self) -> usize {
        self.tcp_syn_channel_size
    }

    pub fn tcp_channel_size(&self) -> usize {
        self.tcp_channel_size
    }

    pub fn udp_channel_size(&self) -> usize {
        self.udp_channel_size
    }

    pub fn icmp_channel_size(&self) -> usize {
        self.icmp_channel_size
    }

    pub fn ip_channel_size(&self) -> usize {
        self.ip_channel_size
    }

    pub fn check(&self) -> io::Result<()> {
        if self.ipv4_mtu < Self::IPV4_MIN_MTU {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ipv4_mtu<576"));
        }
        if self.ipv6_mtu < Self::IPV6_MIN_MTU {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ipv6_mtu<1280"));
        }
        if self.ip_fragment_timeout.is_zero() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ip_fragment_timeout is zero"));
        }
        if self.tcp_max_half_open == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tcp_max_half_open is zero"));
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
            ipv4_mtu: 1500,
            ipv6_mtu: 1500,
            ip_fragment_timeout: Duration::from_secs(10),
            validate_checksums: true,
            tcp_max_half_open: 1024,
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

#[derive(Copy, Clone, Debug, Default)]
pub struct IpStackConfigBuilder {
    config: IpStackConfig,
}

impl IpStackConfigBuilder {
    pub fn ipv4_mtu(mut self, ipv4_mtu: u16) -> Self {
        self.config.ipv4_mtu = ipv4_mtu;
        self
    }

    pub fn mtu(self, mtu: u16) -> Self {
        self.ipv4_mtu(mtu).ipv6_mtu(mtu)
    }

    pub fn ipv6_mtu(mut self, ipv6_mtu: u16) -> Self {
        self.config.ipv6_mtu = ipv6_mtu;
        self
    }

    pub fn ip_fragment_timeout(mut self, ip_fragment_timeout: Duration) -> Self {
        self.config.ip_fragment_timeout = ip_fragment_timeout;
        self
    }

    pub fn validate_checksums(mut self, validate_checksums: bool) -> Self {
        self.config.validate_checksums = validate_checksums;
        self
    }

    pub fn tcp_max_half_open(mut self, tcp_max_half_open: usize) -> Self {
        self.config.tcp_max_half_open = tcp_max_half_open;
        self
    }

    pub fn tcp_config(mut self, tcp_config: crate::tcp::TcpConfig) -> Self {
        self.config.tcp_config = tcp_config;
        self
    }

    pub fn channel_size(mut self, channel_size: usize) -> Self {
        self.config.channel_size = channel_size;
        self
    }

    pub fn tcp_syn_channel_size(mut self, tcp_syn_channel_size: usize) -> Self {
        self.config.tcp_syn_channel_size = tcp_syn_channel_size;
        self
    }

    pub fn tcp_channel_size(mut self, tcp_channel_size: usize) -> Self {
        self.config.tcp_channel_size = tcp_channel_size;
        self
    }

    pub fn udp_channel_size(mut self, udp_channel_size: usize) -> Self {
        self.config.udp_channel_size = udp_channel_size;
        self
    }

    pub fn icmp_channel_size(mut self, icmp_channel_size: usize) -> Self {
        self.config.icmp_channel_size = icmp_channel_size;
        self
    }

    pub fn ip_channel_size(mut self, ip_channel_size: usize) -> Self {
        self.config.ip_channel_size = ip_channel_size;
        self
    }

    pub fn build(self) -> IpStackConfig {
        self.config
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn rejects_ipv6_mtu_below_minimum() {
        let err = IpStackConfig::builder()
            .ipv6_mtu(IpStackConfig::IPV6_MIN_MTU - 1)
            .build()
            .check()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn mtu_builder_alias_sets_both_mtus() {
        let config = IpStackConfig::builder().mtu(1400).build();
        assert_eq!(config.ipv4_mtu(), 1400);
        assert_eq!(config.ipv6_mtu(), 1400);
    }
}

/// Context information of protocol stack
#[derive(Clone, Debug)]
pub struct IpStack {
    routes: SafeRoutes,
    pub(crate) config: Box<IpStackConfig>,
    pub(crate) inner: Arc<IpStackInner>,
}

#[derive(Debug)]
pub(crate) struct IpStackInner {
    active_state: AtomicBool,
    pub(crate) tcp_half_open: DashSet<NetworkTuple>,
    pub(crate) tcp_stream_map: DashMap<NetworkTuple, Sender<TransportPacket>>,
    pub(crate) tcp_listener_map: DashMap<Option<SocketAddr>, Sender<TransportPacket>>,
    pub(crate) udp_socket_map: DashMap<(Option<SocketAddr>, Option<SocketAddr>), flume::Sender<TransportPacket>>,
    pub(crate) raw_socket_map: DashMap<(Option<IpNextHeaderProtocol>, Option<SocketAddr>), flume::Sender<TransportPacket>>,
    pub(crate) packet_sender: Sender<TransportPacket>,
    bind_addrs: Mutex<HashSet<BindKey>>,
}
type BindKey = (IpNextHeaderProtocol, SocketAddr, Option<SocketAddr>);
impl IpStackInner {
    fn remove_all(&self) {
        self.active_state.store(false, Ordering::SeqCst);
        self.tcp_listener_map.clear();
        self.tcp_stream_map.clear();
        self.udp_socket_map.clear();
        self.raw_socket_map.clear();
    }
    fn check_state(&self) -> io::Result<()> {
        if self.active_state.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(io::Error::other("shutdown"))
        }
    }
    fn check_state_and_remove(&self) -> io::Result<()> {
        let rs = self.check_state();
        if rs.is_err() {
            self.remove_all();
        }
        rs
    }
    pub fn has_tcp_connection(&self, local_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<bool> {
        self.check_state()?;

        if local_addr.is_ipv4() != peer_addr.is_ipv4() {
            return Ok(false);
        }
        // Recorded from ingress (accept) perspective:
        // IP packet direction is peer -> local.
        let key = NetworkTuple {
            src: peer_addr,
            dst: local_addr,
            protocol: IpNextHeaderProtocols::Tcp,
        };

        Ok(self.tcp_stream_map.contains_key(&key))
    }
    pub fn has_tcp_half_open(&self, local_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<bool> {
        self.check_state()?;
        if local_addr.is_ipv4() != peer_addr.is_ipv4() {
            return Ok(false);
        }
        let key = NetworkTuple {
            src: peer_addr,
            dst: local_addr,
            protocol: IpNextHeaderProtocols::Tcp,
        };

        Ok(self.tcp_half_open.contains(&key))
    }
}

/// Send IP packets to the protocol stack using `IpStackSend`
pub struct IpStackSend {
    ip_stack: IpStack,
    ident_fragments_map: Arc<Mutex<HashMap<IdKey, IpFragments>>>,
    notify: Arc<Notify>,
}

impl Drop for IpStackSend {
    fn drop(&mut self) {
        self.notify.notify_one();
        self.ip_stack.inner.remove_all();
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

/// Receive IP packets from the protocol stack using `IpStackRecv`
pub struct IpStackRecv {
    inner: IpStackRecvInner,
    index: usize,
    num: usize,
    sizes: Vec<usize>,
    bufs: Vec<BytesMut>,
}
struct IpStackRecvInner {
    ipv4_mtu: u16,
    ipv6_mtu: u16,
    identification: u16,
    identification_v6: u32,
    packet_receiver: Receiver<TransportPacket>,
    /// A packet taken from the channel that did not fit the caller's buffers.
    pending: Option<TransportPacket>,
}

impl IpStackRecv {
    pub(crate) fn new(ipv4_mtu: u16, ipv6_mtu: u16, packet_receiver: Receiver<TransportPacket>) -> Self {
        let millis = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|v| v.as_millis())
            .unwrap_or(0);
        let inner = IpStackRecvInner {
            ipv4_mtu,
            ipv6_mtu,
            identification: (millis & 0xFFFF) as u16,
            identification_v6: (millis & 0xFFFF_FFFF) as u32,
            packet_receiver,
            pending: None,
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
    pub identification: u32,
}

impl IdKey {
    fn new(src: IpAddr, dst: IpAddr, protocol: IpNextHeaderProtocol, identification: u32) -> Self {
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
/// ```no_run
/// use tcp_ip::tcp::TcpListener;
/// #[cfg(not(feature = "global-ip-stack"))]
/// async fn example() -> std::io::Result<()> {
///     let (ip_stack, ip_stack_send, ip_stack_recv) = tcp_ip::ip_stack(Default::default())?;
///     // Use ip_stack_send and ip_stack_recv to interface
///     // with the input and output of IP packets.
///     // ...
///     let mut tcp_listener = TcpListener::bind_all(ip_stack.clone()).await?;
///     Ok(())
/// }
/// ```
#[cfg(not(feature = "global-ip-stack"))]
pub fn ip_stack(config: IpStackConfig) -> io::Result<(IpStack, IpStackSend, IpStackRecv)> {
    ip_stack0(config)
}

/// Create a user-space protocol stack.
///
/// # Examples
/// ```no_run
/// use tcp_ip::tcp::TcpListener;
/// #[cfg(feature = "global-ip-stack")]
/// async fn example() -> std::io::Result<()> {
///     let (ip_stack_send, ip_stack_recv) = tcp_ip::ip_stack(Default::default())?;
///     // Use ip_stack_send and ip_stack_recv to interface
///     // with the input and output of IP packets.
///     // ...
///     let mut tcp_listener = TcpListener::bind_all().await?;
///     Ok(())
/// }
/// ```
#[cfg(feature = "global-ip-stack")]
pub fn ip_stack(config: IpStackConfig) -> io::Result<(IpStackSend, IpStackRecv)> {
    let (ip_stack, ip_stack_send, ip_stack_recv) = ip_stack0(config)?;
    IpStack::set(ip_stack);
    Ok((ip_stack_send, ip_stack_recv))
}
fn ip_stack0(config: IpStackConfig) -> io::Result<(IpStack, IpStackSend, IpStackRecv)> {
    config.check()?;
    let (packet_sender, packet_receiver) = channel(config.channel_size());
    let ip_stack = IpStack::new(config, packet_sender);
    let ip_stack_send = IpStackSend::new(ip_stack.clone());
    let ip_stack_recv = IpStackRecv::new(ip_stack.config.ipv4_mtu(), ip_stack.config.ipv6_mtu(), packet_receiver);
    {
        let ident_fragments_map = ip_stack_send.ident_fragments_map.clone();
        let notify = ip_stack_send.notify.clone();
        let timeout = ip_stack.config.ip_fragment_timeout();
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
    pub fn routes(&self) -> &SafeRoutes {
        &self.routes
    }
    /// Check whether a TCP stream entry exists for the given local/peer socket pair.
    pub fn has_tcp_connection(&self, local_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<bool> {
        self.inner.has_tcp_connection(local_addr, peer_addr)
    }
    pub fn has_tcp_half_open(&self, local_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<bool> {
        self.inner.has_tcp_half_open(local_addr, peer_addr)
    }
}
impl IpStack {
    pub(crate) fn new(config: IpStackConfig, packet_sender: Sender<TransportPacket>) -> Self {
        Self {
            routes: Default::default(),
            config: Box::new(config),
            inner: Arc::new(IpStackInner {
                active_state: AtomicBool::new(true),
                tcp_half_open: Default::default(),
                tcp_stream_map: Default::default(),
                tcp_listener_map: Default::default(),
                udp_socket_map: Default::default(),
                raw_socket_map: Default::default(),
                packet_sender,
                bind_addrs: Default::default(),
            }),
        }
    }
    pub(crate) fn add_ip_socket(
        &self,
        protocol: Option<IpNextHeaderProtocol>,
        local_addr: Option<SocketAddr>,
        packet_sender: flume::Sender<TransportPacket>,
    ) -> io::Result<()> {
        Self::add_socket0(&self.inner, &self.inner.raw_socket_map, (protocol, local_addr), packet_sender)
    }
    pub(crate) fn add_udp_socket(
        &self,
        local_addr: Option<SocketAddr>,
        peer_addr: Option<SocketAddr>,
        packet_sender: flume::Sender<TransportPacket>,
    ) -> io::Result<()> {
        Self::add_socket0(&self.inner, &self.inner.udp_socket_map, (local_addr, peer_addr), packet_sender)
    }

    pub(crate) fn replace_udp_socket(
        &self,
        old: (Option<SocketAddr>, Option<SocketAddr>),
        new: (Option<SocketAddr>, Option<SocketAddr>),
    ) -> io::Result<()> {
        let packet_sender = if let Some(v) = self.inner.udp_socket_map.get(&old) {
            v.value().clone()
        } else {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        };
        Self::add_socket0(&self.inner, &self.inner.udp_socket_map, new, packet_sender)?;
        _ = self.inner.udp_socket_map.remove(&old);
        Ok(())
    }

    pub(crate) fn add_tcp_listener(&self, local_addr: Option<SocketAddr>, packet_sender: Sender<TransportPacket>) -> io::Result<()> {
        Self::add_socket0(&self.inner, &self.inner.tcp_listener_map, local_addr, packet_sender)
    }
    pub(crate) fn remove_tcp_listener(&self, local_addr: &Option<SocketAddr>) {
        self.inner.tcp_listener_map.remove(local_addr);
    }
    pub(crate) fn add_tcp_socket(&self, network_tuple: NetworkTuple, packet_sender: Sender<TransportPacket>) -> io::Result<()> {
        Self::add_socket0(&self.inner, &self.inner.tcp_stream_map, network_tuple, packet_sender)
    }
    pub(crate) fn add_tcp_half_open(&self, network_tuple: NetworkTuple) {
        self.inner.tcp_half_open.insert(network_tuple);
    }
    pub(crate) fn remove_tcp_half_open(&self, network_tuple: &NetworkTuple) {
        self.inner.tcp_half_open.remove(network_tuple);
    }
    pub(crate) fn remove_tcp_socket(&self, network_tuple: &NetworkTuple) {
        self.inner.tcp_stream_map.remove(network_tuple);
    }
    pub(crate) fn remove_udp_socket(&self, local_addr: Option<SocketAddr>, peer_addr: Option<SocketAddr>) {
        self.inner.udp_socket_map.remove(&(local_addr, peer_addr));
    }
    pub(crate) fn remove_ip_socket(&self, protocol: Option<IpNextHeaderProtocol>, local_addr: Option<SocketAddr>) {
        self.inner.raw_socket_map.remove(&(protocol, local_addr));
    }
    fn add_socket0<K: Eq + PartialEq + Hash, V>(
        ip_stack_inner: &IpStackInner,
        map: &DashMap<K, V>,
        local_addr: K,
        packet_sender: V,
    ) -> io::Result<()> {
        ip_stack_inner.check_state()?;
        let entry = map.entry(local_addr);
        let rs = match entry {
            Entry::Occupied(_entry) => Err(io::Error::from(io::ErrorKind::AddrInUse)),
            Entry::Vacant(entry) => {
                entry.insert(packet_sender);
                Ok(())
            }
        };
        ip_stack_inner.check_state_and_remove()?;
        rs
    }
    pub(crate) async fn send_packet(&self, transport_packet: TransportPacket) -> io::Result<()> {
        match self.inner.packet_sender.send(transport_packet).await {
            Ok(_) => Ok(()),
            Err(_) => Err(io::Error::new(io::ErrorKind::WriteZero, "ip stack close")),
        }
    }
    pub(crate) fn bind(&self, protocol: IpNextHeaderProtocol, addr: &mut SocketAddr, peer: Option<SocketAddr>) -> io::Result<BindAddr> {
        let bind_address = self.inner.add_bind_addr(protocol, *addr, peer, true)?;
        *addr = bind_address;
        Ok(BindAddr {
            protocol,
            addr: bind_address,
            peer,
            inner: self.inner.clone(),
        })
    }
    pub(crate) fn bind_ip(&self, protocol: IpNextHeaderProtocol, addr: SocketAddr) -> io::Result<BindAddr> {
        _ = self.inner.add_bind_addr(protocol, addr, None, false)?;
        Ok(BindAddr {
            protocol,
            addr,
            peer: None,
            inner: self.inner.clone(),
        })
    }
}

impl IpStackSend {
    pub async fn send_ipv4_payload(
        &self,
        protocol: IpNextHeaderProtocol,
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        payload: BytesMut,
    ) -> io::Result<()> {
        let network_tuple = convert_ip_payload_network_tuple(protocol, src_ip, dest_ip, &payload)?;
        if let Some(sender) = self.get_sender(protocol, &network_tuple) {
            _ = sender.send(TransportPacket::new(payload.freeze(), network_tuple)).await;
        }
        Ok(())
    }
    pub async fn send_ipv6_payload(
        &self,
        protocol: IpNextHeaderProtocol,
        src_ip: Ipv6Addr,
        dest_ip: Ipv6Addr,
        payload: BytesMut,
    ) -> io::Result<()> {
        let network_tuple = convert_ip_payload_network_tuple_v6(protocol, src_ip, dest_ip, &payload)?;
        if let Some(sender) = self.get_sender(protocol, &network_tuple) {
            _ = sender.send(TransportPacket::new(payload.freeze(), network_tuple)).await;
        }
        Ok(())
    }
    /// Send the IP packet to this protocol stack.
    pub async fn send_ip_packet(&self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "ip packet is empty"));
        }
        let p = buf[0] >> 4;
        match p {
            4 => {
                let Some(packet) = Ipv4Packet::new(buf) else {
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                };
                let header_len = packet.get_header_length() as usize * 4;
                let total_length = packet.get_total_length() as usize;
                if header_len < 20 || total_length < header_len || buf.len() < total_length {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid ipv4 packet length"));
                }
                if self.ip_stack.config.validate_checksums() {
                    let header = &buf[..header_len];
                    let checksum = crate::checksum::checksum(header, 5);
                    if checksum != packet.get_checksum() {
                        log::debug!(
                            "drop ipv4 packet with invalid header checksum: expected={checksum:#06x} actual={:#06x}",
                            packet.get_checksum()
                        );
                        return Ok(());
                    }
                }
                let Some(packet) = Ipv4Packet::new(&buf[..total_length]) else {
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                };

                let id_key = convert_id_key(&packet);

                let Some(network_tuple) = self.prepare_ipv4_fragments(&packet, id_key)? else {
                    return Ok(());
                };
                if let Some(sender) = self.get_sender(packet.get_next_level_protocol(), &network_tuple) {
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
                let total_length = 40 + packet.get_payload_length() as usize;
                if buf.len() < total_length {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid ipv6 packet length"));
                }
                let Some(packet) = Ipv6Packet::new(&buf[..total_length]) else {
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                };
                let Some(info) = crate::ipv6::walk_extension_headers(packet.get_next_header(), packet.payload())? else {
                    // No Next Header: nothing to deliver.
                    return Ok(());
                };
                let l4_payload = &packet.payload()[info.payload_offset..];
                match info.fragment {
                    Some(ref fragment) if fragment.is_segmented() => {
                        let id_key = convert_id_key_v6(&packet, info.protocol, fragment.identification);
                        let Some(network_tuple) = self.prepare_ipv6_fragments(&packet, info.protocol, fragment, id_key, l4_payload)? else {
                            return Ok(());
                        };
                        if let Some(sender) = self.get_sender(info.protocol, &network_tuple) {
                            let rs = self
                                .transmit_ipv6_fragment(sender, fragment, id_key, network_tuple, l4_payload)
                                .await;
                            if rs.is_err() {
                                self.clear_fragment_cache(&id_key);
                            }
                            rs
                        } else {
                            self.clear_fragment_cache(&id_key);
                            Ok(())
                        }
                    }
                    _ => {
                        let network_tuple =
                            convert_ip_payload_network_tuple_v6(info.protocol, packet.get_source(), packet.get_destination(), l4_payload)?;
                        if let Some(fragment) = &info.fragment {
                            // An atomic fragment: confirm that the id is not occupied.
                            self.clear_fragment_cache(&convert_id_key_v6(&packet, info.protocol, fragment.identification));
                        }
                        if !self.validate_l4_checksum(l4_payload, network_tuple) {
                            return Ok(());
                        }
                        if let Some(sender) = self.get_sender(info.protocol, &network_tuple) {
                            _ = sender
                                .send(TransportPacket::new(Bytes::copy_from_slice(l4_payload), network_tuple))
                                .await;
                        }
                        Ok(())
                    }
                }
            }
            _ => Err(io::Error::from(io::ErrorKind::InvalidInput)),
        }
    }
    fn get_sender(&self, protocol: IpNextHeaderProtocol, network_tuple: &NetworkTuple) -> Option<SenderBox<TransportPacket>> {
        let sender = match protocol {
            IpNextHeaderProtocols::Tcp => self.get_tcp_sender(network_tuple),
            IpNextHeaderProtocols::Udp => self.get_udp_sender(network_tuple),
            _ => None,
        };
        sender.or_else(|| self.get_raw_sender(protocol, network_tuple))
    }
    fn get_tcp_sender(&self, network_tuple: &NetworkTuple) -> Option<SenderBox<TransportPacket>> {
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
    fn get_udp_sender(&self, network_tuple: &NetworkTuple) -> Option<SenderBox<TransportPacket>> {
        let stack = &self.ip_stack.inner;
        if let Some(udp) = stack.udp_socket_map.get(&(Some(network_tuple.dst), Some(network_tuple.src))) {
            return Some(SenderBox::Mpmc(udp.value().clone()));
        }
        if let Some(udp) = stack.udp_socket_map.get(&(Some(network_tuple.dst), None)) {
            Some(SenderBox::Mpmc(udp.value().clone()))
        } else {
            let dst = SocketAddr::new(default_ip(network_tuple.is_ipv4()), network_tuple.dst.port());
            if let Some(udp) = stack.udp_socket_map.get(&(Some(dst), None)) {
                Some(SenderBox::Mpmc(udp.value().clone()))
            } else if let Some(udp) = stack.udp_socket_map.get(&(Some(default_addr(network_tuple.is_ipv4())), None)) {
                Some(SenderBox::Mpmc(udp.value().clone()))
            } else {
                stack
                    .udp_socket_map
                    .get(&(None, None))
                    .map(|udp| SenderBox::Mpmc(udp.value().clone()))
            }
        }
    }
    fn get_raw_sender(&self, protocol: IpNextHeaderProtocol, network_tuple: &NetworkTuple) -> Option<SenderBox<TransportPacket>> {
        if let Some(v) = self.get_raw_sender0(Some(protocol), network_tuple) {
            Some(v)
        } else {
            self.get_raw_sender0(None, network_tuple)
        }
    }
    fn get_raw_sender0(&self, protocol: Option<IpNextHeaderProtocol>, network_tuple: &NetworkTuple) -> Option<SenderBox<TransportPacket>> {
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
        &self,
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
            if let Some(buf) = self.merge_fragments((&packet).into(), !more_fragments, id_key, network_tuple)? {
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
        if !self.validate_l4_checksum(&buf, network_tuple) {
            return Ok(());
        }
        _ = sender.send(TransportPacket::new(buf.freeze(), network_tuple)).await;
        Ok(())
    }
    async fn transmit_ipv6_fragment(
        &self,
        sender: SenderBox<TransportPacket>,
        fragment: &crate::ipv6::Ipv6FragmentInfo,
        id_key: IdKey,
        network_tuple: NetworkTuple,
        l4_payload: &[u8],
    ) -> io::Result<()> {
        let ip_fragment = IpFragment {
            offset: fragment.offset,
            payload: l4_payload.into(),
        };
        let Some(buf) = self.merge_fragments(ip_fragment, !fragment.more_fragments, id_key, network_tuple)? else {
            // Need to wait for all shards to arrive
            return Ok(());
        };
        if !self.validate_l4_checksum(&buf, network_tuple) {
            return Ok(());
        }
        _ = sender.send(TransportPacket::new(buf.freeze(), network_tuple)).await;
        Ok(())
    }
    fn validate_l4_checksum(&self, payload: &[u8], network_tuple: NetworkTuple) -> bool {
        if !self.ip_stack.config.validate_checksums() {
            return true;
        }
        let expected_checksum = |skipword: usize, protocol: IpNextHeaderProtocol| match (network_tuple.src.ip(), network_tuple.dst.ip()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => crate::checksum::ipv4_checksum(payload, skipword, &src, &dst, protocol),
            (IpAddr::V6(src), IpAddr::V6(dst)) => crate::checksum::ipv6_checksum(payload, skipword, &src, &dst, protocol),
            (_, _) => 0,
        };
        match network_tuple.protocol {
            IpNextHeaderProtocols::Tcp => {
                let Some(tcp_packet) = TcpPacket::new(payload) else {
                    log::debug!("drop tcp packet with invalid header");
                    return false;
                };
                let checksum = expected_checksum(8, IpNextHeaderProtocols::Tcp);
                if checksum != tcp_packet.get_checksum() {
                    log::debug!(
                        "drop tcp packet with invalid checksum: expected={checksum:#06x} actual={:#06x}",
                        tcp_packet.get_checksum()
                    );
                    return false;
                }
                true
            }
            IpNextHeaderProtocols::Udp => {
                let Some(udp_packet) = UdpPacket::new(payload) else {
                    log::debug!("drop udp packet with invalid header");
                    return false;
                };
                if udp_packet.get_checksum() == 0 {
                    // A zero checksum means "not computed" for IPv4,
                    // but is illegal for IPv6 (RFC 8200 §8.1).
                    if network_tuple.src.is_ipv4() {
                        return true;
                    }
                    log::debug!("drop udp packet with zero checksum over ipv6");
                    return false;
                }
                let checksum = expected_checksum(3, IpNextHeaderProtocols::Udp);
                if checksum != udp_packet.get_checksum() {
                    log::debug!(
                        "drop udp packet with invalid checksum: expected={checksum:#06x} actual={:#06x}",
                        udp_packet.get_checksum()
                    );
                    return false;
                }
                true
            }
            _ => true,
        }
    }
    fn prepare_ipv4_fragments(&self, ip_packet: &Ipv4Packet<'_>, id_key: IdKey) -> io::Result<Option<NetworkTuple>> {
        let offset = ip_packet.get_fragment_offset();
        let network_tuple = if offset == 0
            || (ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp
                && ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp)
        {
            // No segmentation or the first segmentation
            convert_network_tuple(ip_packet)?
        } else {
            let mut guard = self.ident_fragments_map.lock();
            if !guard.contains_key(&id_key) && guard.len() >= MAX_FRAGMENT_ENTRIES {
                log::debug!("drop ipv4 fragment: fragment cache full");
                return Ok(None);
            }
            let p = guard.entry(id_key).or_default();

            if let Some(v) = p.network_tuple {
                v
            } else {
                // Perhaps the first IP segment has not yet arrived,
                // so the network tuple cannot be obtained.
                let last_fragment = ip_packet.get_flags() & Ipv4Flags::MoreFragments != Ipv4Flags::MoreFragments;
                if last_fragment {
                    p.last_offset.replace(ip_packet.get_fragment_offset() << 3);
                }
                p.add_fragment(ip_packet.into(), last_fragment)?;
                return Ok(None);
            }
        };
        Ok(Some(network_tuple))
    }
    fn prepare_ipv6_fragments(
        &self,
        ip_packet: &Ipv6Packet<'_>,
        protocol: IpNextHeaderProtocol,
        fragment: &crate::ipv6::Ipv6FragmentInfo,
        id_key: IdKey,
        l4_payload: &[u8],
    ) -> io::Result<Option<NetworkTuple>> {
        let network_tuple = if fragment.offset == 0 || (protocol != IpNextHeaderProtocols::Udp && protocol != IpNextHeaderProtocols::Tcp) {
            // No segmentation or the first segmentation
            convert_ip_payload_network_tuple_v6(protocol, ip_packet.get_source(), ip_packet.get_destination(), l4_payload)?
        } else {
            let mut guard = self.ident_fragments_map.lock();
            if !guard.contains_key(&id_key) && guard.len() >= MAX_FRAGMENT_ENTRIES {
                log::debug!("drop ipv6 fragment: fragment cache full");
                return Ok(None);
            }
            let p = guard.entry(id_key).or_default();

            if let Some(v) = p.network_tuple {
                v
            } else {
                // Perhaps the first IP segment has not yet arrived,
                // so the network tuple cannot be obtained.
                let last_fragment = !fragment.more_fragments;
                if last_fragment {
                    p.last_offset.replace(fragment.offset);
                }
                p.add_fragment(
                    IpFragment {
                        offset: fragment.offset,
                        payload: l4_payload.into(),
                    },
                    last_fragment,
                )?;
                return Ok(None);
            }
        };
        Ok(Some(network_tuple))
    }
    fn merge_fragments(
        &self,
        fragment: IpFragment,
        last_fragment: bool,
        id_key: IdKey,
        network_tuple: NetworkTuple,
    ) -> io::Result<Option<BytesMut>> {
        let mut map = self.ident_fragments_map.lock();
        if !map.contains_key(&id_key) && map.len() >= MAX_FRAGMENT_ENTRIES {
            log::debug!("drop ip fragment: fragment cache full");
            return Ok(None);
        }
        let ip_fragments = map
            .entry(id_key)
            .and_modify(|p| {
                p.update_time();
                // Fragments buffered before the first one arrived leave the
                // tuple unresolved; record it so later fragments can use it.
                if p.network_tuple.is_none() {
                    p.network_tuple.replace(network_tuple);
                }
            })
            .or_insert_with(|| IpFragments::new(network_tuple));

        let offset = fragment.offset;
        if last_fragment {
            ip_fragments.last_offset.replace(offset);
        }
        ip_fragments.add_fragment(fragment, last_fragment)?;

        if ip_fragments.is_complete() {
            //This place cannot be None
            let mut fragments = map.remove(&id_key).unwrap();
            fragments.bufs.sort_by_key(|ip_fragment1| ip_fragment1.offset);
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
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "bufs too short"));
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
                let mtu = self.inner.ipv4_mtu.max(self.inner.ipv6_mtu) as usize;
                for _ in 0..128 {
                    self.bufs.push(BytesMut::zeroed(mtu));
                }
            }
            self.num = self.inner.recv_ip_packet(&mut self.bufs, &mut self.sizes).await?;
            if self.num == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read 0"));
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
        let mut packet = if let Some(packet) = self.pending.take() {
            packet
        } else if let Some(packet) = self.packet_receiver.recv().await {
            packet
        } else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "close"));
        };
        let mut total = 0;
        loop {
            // Conservative estimate; only used to stop batching, the first
            // packet is always attempted so single-packet semantics are kept.
            if total > 0 && self.fragments_needed(&packet) > bufs.len() - total {
                self.pending = Some(packet);
                break;
            }
            let rs = match (packet.network_tuple.src.is_ipv6(), packet.network_tuple.dst.is_ipv6()) {
                (true, true) => self.split_ipv6_packet(&mut bufs[total..], &mut sizes[total..], &packet),
                (false, false) => self.split_ip_packet(&mut bufs[total..], &mut sizes[total..], &packet),
                (_, _) => Err(io::Error::new(io::ErrorKind::InvalidInput, "address error")),
            };
            match rs {
                Ok(n) => total += n,
                Err(e) => {
                    if total == 0 {
                        return Err(e);
                    }
                    // Deliver what was already split; the error surfaces
                    // deterministically when this packet is retried next call.
                    self.pending = Some(packet);
                    break;
                }
            }
            if total >= bufs.len() {
                break;
            }
            // Drain whatever is already queued without waiting.
            match self.packet_receiver.try_recv() {
                Ok(next) => packet = next,
                Err(_) => break,
            }
        }
        Ok(total)
    }
    /// Upper bound of the IP packets `packet` splits into.
    fn fragments_needed(&self, packet: &TransportPacket) -> usize {
        let len = packet.buf.len();
        if packet.network_tuple.src.is_ipv6() {
            let mtu = self.ipv6_mtu as usize;
            if 40 + len <= mtu {
                1
            } else {
                len.div_ceil((mtu - 48) & !0b111)
            }
        } else {
            let mtu = self.ipv4_mtu as usize;
            if 20 + len <= mtu {
                1
            } else {
                len.div_ceil((mtu - 20) & !0b111)
            }
        }
    }
    fn split_ipv6_packet<B: AsMut<[u8]>>(&mut self, bufs: &mut [B], sizes: &mut [usize], packet: &TransportPacket) -> io::Result<usize> {
        const IPV6_HEADER_SIZE: usize = 40;
        const FRAGMENT_HEADER_SIZE: usize = 8;
        let (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) = (packet.network_tuple.src.ip(), packet.network_tuple.dst.ip()) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "address error"));
        };
        let protocol = packet.network_tuple.protocol;
        let mtu = self.ipv6_mtu as usize;

        let write_ipv6_header = |buf: &mut [u8], next_header: IpNextHeaderProtocol, payload_length: usize| {
            buf[0] = 6 << 4; // Version (6) + Traffic Class
            buf[1..4].fill(0); // Traffic Class + Flow Label
            buf[4..6].copy_from_slice(&(payload_length as u16).to_be_bytes());
            buf[6] = next_header.0;
            buf[7] = 64; // Hop Limit
            buf[8..24].copy_from_slice(&src_ip.octets());
            buf[24..40].copy_from_slice(&dst_ip.octets());
        };

        if IPV6_HEADER_SIZE + packet.buf.len() <= mtu {
            let total_length = IPV6_HEADER_SIZE + packet.buf.len();
            let buf = bufs[0].as_mut();
            if buf.len() < total_length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("bufs[0] too short.{total_length}>{:?}", buf.len()),
                ));
            }
            write_ipv6_header(buf, protocol, packet.buf.len());
            buf[IPV6_HEADER_SIZE..total_length].copy_from_slice(&packet.buf);
            sizes[0] = total_length;
            return Ok(1);
        }
        // The payload exceeds the MTU: split it across Fragment extension headers (RFC 8200 §4.5).
        self.identification_v6 = self.identification_v6.wrapping_sub(1);
        let identification = self.identification_v6;
        let max_fragment_data = (mtu - IPV6_HEADER_SIZE - FRAGMENT_HEADER_SIZE) & !0b111;
        let mut offset = 0;
        let mut total_packets = 0;

        while offset < packet.buf.len() {
            let remaining = packet.buf.len() - offset;
            let fragment_size = remaining.min(max_fragment_data);
            let total_length = IPV6_HEADER_SIZE + FRAGMENT_HEADER_SIZE + fragment_size;
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
            let more_fragments = remaining > fragment_size;
            assert_eq!(offset & 0b111, 0, "Offset must be a multiple of 8");
            let offset_flags = (offset as u16 & !0b111) | more_fragments as u16;

            write_ipv6_header(buf, IpNextHeaderProtocols::Ipv6Frag, FRAGMENT_HEADER_SIZE + fragment_size);
            let fragment_header = &mut buf[IPV6_HEADER_SIZE..IPV6_HEADER_SIZE + FRAGMENT_HEADER_SIZE];
            fragment_header[0] = protocol.0;
            fragment_header[1] = 0; // Reserved
            fragment_header[2..4].copy_from_slice(&offset_flags.to_be_bytes());
            fragment_header[4..8].copy_from_slice(&identification.to_be_bytes());

            let data_start = IPV6_HEADER_SIZE + FRAGMENT_HEADER_SIZE;
            buf[data_start..total_length].copy_from_slice(&packet.buf[offset..offset + fragment_size]);
            offset += fragment_size;
            sizes[total_packets] = total_length;
            total_packets += 1;
        }
        Ok(total_packets)
    }
    fn split_ip_packet<B: AsMut<[u8]>>(&mut self, bufs: &mut [B], sizes: &mut [usize], packet: &TransportPacket) -> io::Result<usize> {
        let mtu = self.ipv4_mtu;
        self.identification = self.identification.wrapping_sub(1);
        let identification = self.identification;
        let mut offset = 0;
        let mut total_packets = 0;

        const IPV4_HEADER_SIZE: usize = 20; // IPv4 header fixed size
        let max_payload_size = mtu as usize - IPV4_HEADER_SIZE;
        let max_payload_size_8 = max_payload_size & !0b111;
        let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (packet.network_tuple.src.ip(), packet.network_tuple.dst.ip()) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "address error"));
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

            let checksum = crate::checksum::checksum(ip_header, 5);
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
    pub buf: Bytes,
    pub network_tuple: NetworkTuple,
}

impl TransportPacket {
    pub fn new(buf: Bytes, network_tuple: NetworkTuple) -> Self {
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
        if self.bufs.iter().any(|fragment| fragment.offset == ip_fragment.offset) {
            log::debug!("ignore duplicate ip fragment at offset {}", ip_fragment.offset);
            return Ok(());
        }
        if self.bufs.len() >= MAX_FRAGMENTS_PER_PACKET {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many IP fragments"));
        }
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
    let protocol = packet.get_next_level_protocol();
    let src_ip = packet.get_source();
    let dest_ip = packet.get_destination();
    convert_ip_payload_network_tuple(protocol, src_ip, dest_ip, packet.payload())
}
fn convert_ip_payload_network_tuple(
    protocol: IpNextHeaderProtocol,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    payload: &[u8],
) -> io::Result<NetworkTuple> {
    let (src_port, dest_port) = match protocol {
        IpNextHeaderProtocols::Tcp => {
            let Some(tcp_packet) = pnet_packet::tcp::TcpPacket::new(payload) else {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            };
            (tcp_packet.get_source(), tcp_packet.get_destination())
        }
        IpNextHeaderProtocols::Udp => {
            let Some(udp_packet) = pnet_packet::udp::UdpPacket::new(payload) else {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            };
            (udp_packet.get_source(), udp_packet.get_destination())
        }
        _ => (0, 0),
    };

    let src_addr = SocketAddrV4::new(src_ip, src_port);
    let dest_addr = SocketAddrV4::new(dest_ip, dest_port);
    let network_tuple = NetworkTuple::new(src_addr.into(), dest_addr.into(), protocol);
    Ok(network_tuple)
}
fn convert_ip_payload_network_tuple_v6(
    protocol: IpNextHeaderProtocol,
    src_ip: Ipv6Addr,
    dest_ip: Ipv6Addr,
    payload: &[u8],
) -> io::Result<NetworkTuple> {
    let (src_port, dest_port) = match protocol {
        IpNextHeaderProtocols::Tcp => {
            let Some(tcp_packet) = pnet_packet::tcp::TcpPacket::new(payload) else {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            };
            (tcp_packet.get_source(), tcp_packet.get_destination())
        }
        IpNextHeaderProtocols::Udp => {
            let Some(udp_packet) = pnet_packet::udp::UdpPacket::new(payload) else {
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
    IdKey::new(src_ip.into(), dest_ip.into(), protocol, identification as u32)
}

fn convert_id_key_v6(packet: &Ipv6Packet, protocol: IpNextHeaderProtocol, identification: u32) -> IdKey {
    IdKey::new(
        packet.get_source().into(),
        packet.get_destination().into(),
        protocol,
        identification,
    )
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
#[derive(Clone, Default, Debug)]
pub struct SafeRoutes {
    routes: Arc<Mutex<Routes>>,
}
impl SafeRoutes {
    pub(crate) fn check_bind_ip(&self, ip: IpAddr) -> io::Result<()> {
        if check_ip(ip).is_ok() && !self.exists_ip(&ip) {
            return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "cannot assign requested address"));
        }
        Ok(())
    }
    pub(crate) fn exists_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.exists_v4(ip),
            IpAddr::V6(ip) => self.exists_v6(ip),
        }
    }
    pub(crate) fn exists_v4(&self, ip: &Ipv4Addr) -> bool {
        self.routes.lock().exists_v4(ip)
    }
    pub(crate) fn exists_v6(&self, ip: &Ipv6Addr) -> bool {
        self.routes.lock().exists_v6(ip)
    }
    pub fn ipv4_list(&self) -> Vec<Ipv4Addr> {
        self.routes.lock().v4_list.clone()
    }
    pub fn ipv6_list(&self) -> Vec<Ipv6Addr> {
        self.routes.lock().v6_list.clone()
    }
    pub fn route(&self, dst: IpAddr) -> Option<IpAddr> {
        match dst {
            IpAddr::V4(ip) => self.route_v4(ip).map(|v| v.into()),
            IpAddr::V6(ip) => self.route_v6(ip).map(|v| v.into()),
        }
    }
    pub fn route_v4(&self, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        self.routes.lock().route_v4(dst)
    }
    pub fn route_v6(&self, dst: Ipv6Addr) -> Option<Ipv6Addr> {
        self.routes.lock().route_v6(dst)
    }
    pub fn add_v4(&self, dest: Ipv4Addr, mask: Ipv4Addr, ip: Ipv4Addr) -> io::Result<()> {
        self.routes.lock().add_v4(dest, mask, ip)
    }
    pub fn add_v6(&self, dest: Ipv6Addr, mask: Ipv6Addr, ip: Ipv6Addr) -> io::Result<()> {
        self.routes.lock().add_v6(dest, mask, ip)
    }
    pub fn remove_v4(&self, dest: Ipv4Addr, mask: Ipv4Addr) -> io::Result<()> {
        self.routes.lock().remove_v4(dest, mask)
    }
    pub fn remove_v6(&self, dest: Ipv6Addr, mask: Ipv6Addr) -> io::Result<()> {
        self.routes.lock().remove_v6(dest, mask)
    }
    pub fn clear_v4(&self) {
        self.routes.lock().clear_v4()
    }
    pub fn clear_v6(&self) {
        self.routes.lock().clear_v6()
    }
    pub fn set_default_v4(&self, ip: Ipv4Addr) {
        self.routes.lock().set_default_v4(ip)
    }
    pub fn set_default_v6(&self, ip: Ipv6Addr) {
        self.routes.lock().set_default_v6(ip)
    }
    pub fn default_v4(&self) -> Option<Ipv4Addr> {
        self.routes.lock().default_v4()
    }
    pub fn default_v6(&self) -> Option<Ipv6Addr> {
        self.routes.lock().default_v6()
    }
}

#[derive(Default, Debug)]
struct Routes {
    v4_list: Vec<Ipv4Addr>,
    default_v4: Option<Ipv4Addr>,
    v4_table: Vec<(u32, u32, Ipv4Addr)>,
    v6_list: Vec<Ipv6Addr>,
    default_v6: Option<Ipv6Addr>,
    v6_table: Vec<(u128, u128, Ipv6Addr)>,
}
impl Routes {
    fn exists_v4(&self, ip: &Ipv4Addr) -> bool {
        if self.v4_list.is_empty() {
            return true;
        }
        self.v4_list.contains(ip)
    }
    fn exists_v6(&self, ip: &Ipv6Addr) -> bool {
        if self.v6_list.is_empty() {
            return true;
        }
        self.v6_list.contains(ip)
    }
    fn route_v4(&self, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        let dst = u32::from(dst);
        for (dest_cur, mask_cur, ip_cur) in self.v4_table.iter() {
            if dst & *mask_cur == *dest_cur {
                return Some(*ip_cur);
            }
        }
        self.default_v4
    }
    fn route_v6(&self, dst: Ipv6Addr) -> Option<Ipv6Addr> {
        let dst = u128::from(dst);
        for (dest_cur, mask_cur, ip_cur) in self.v6_table.iter() {
            if dst & *mask_cur == *dest_cur {
                return Some(*ip_cur);
            }
        }
        self.default_v6
    }
    fn add_v4(&mut self, dest: Ipv4Addr, mask: Ipv4Addr, ip: Ipv4Addr) -> io::Result<()> {
        let mask = u32::from(mask);
        if mask.count_ones() != mask.leading_ones() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid mask"));
        }
        if !self.v4_list.contains(&ip) {
            self.v4_list.push(ip);
        }
        let dest = u32::from(dest) & mask;
        for (dest_cur, mask_cur, ip_cur) in self.v4_table.iter_mut() {
            if dest == *dest_cur && mask == *mask_cur {
                *ip_cur = ip;
                return Ok(());
            }
        }
        self.v4_table.push((dest, mask, ip));
        self.v4_table.sort_by_key(|b| std::cmp::Reverse(b.1));
        Ok(())
    }
    fn add_v6(&mut self, dest: Ipv6Addr, mask: Ipv6Addr, ip: Ipv6Addr) -> io::Result<()> {
        let mask = u128::from(mask);
        if mask.count_ones() != mask.leading_ones() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid mask"));
        }
        if !self.v6_list.contains(&ip) {
            self.v6_list.push(ip);
        }
        let dest = u128::from(dest) & mask;
        for (dest_cur, mask_cur, ip_cur) in self.v6_table.iter_mut() {
            if dest == *dest_cur && mask == *mask_cur {
                *ip_cur = ip;
                return Ok(());
            }
        }
        self.v6_table.push((dest, mask, ip));
        self.v6_table.sort_by_key(|b| std::cmp::Reverse(b.1));
        Ok(())
    }
    fn remove_v4(&mut self, dest: Ipv4Addr, mask: Ipv4Addr) -> io::Result<()> {
        let mask = u32::from(mask);
        let dest = u32::from(dest) & mask;
        let len = self.v4_table.len();

        self.v4_table
            .retain(|(dest_cur, mask_cur, _)| !(dest == *dest_cur && mask == *mask_cur));
        if len == self.v4_table.len() {
            Err(io::Error::new(io::ErrorKind::NotFound, "not found route"))
        } else {
            self.v4_list = self.v4_table.iter().map(|v| v.2).collect();
            Ok(())
        }
    }
    fn remove_v6(&mut self, dest: Ipv6Addr, mask: Ipv6Addr) -> io::Result<()> {
        let mask = u128::from(mask);
        let dest = u128::from(dest) & mask;
        let len = self.v6_table.len();
        self.v6_table
            .retain(|(dest_cur, mask_cur, _)| !(dest == *dest_cur && mask == *mask_cur));
        if len == self.v6_table.len() {
            Err(io::Error::new(io::ErrorKind::NotFound, "not found route"))
        } else {
            self.v6_list = self.v6_table.iter().map(|v| v.2).collect();
            Ok(())
        }
    }
    fn clear_v4(&mut self) {
        self.v4_table.clear();
    }
    fn clear_v6(&mut self) {
        self.v6_table.clear();
    }
    fn set_default_v4(&mut self, ip: Ipv4Addr) {
        if !self.v4_list.contains(&ip) {
            self.v4_list.push(ip);
        }
        self.default_v4 = Some(ip)
    }
    fn set_default_v6(&mut self, ip: Ipv6Addr) {
        if !self.v6_list.contains(&ip) {
            self.v6_list.push(ip);
        }
        self.default_v6 = Some(ip)
    }
    fn default_v4(&self) -> Option<Ipv4Addr> {
        self.default_v4
    }
    fn default_v6(&self) -> Option<Ipv6Addr> {
        self.default_v6
    }
}

impl IpStackInner {
    fn add_bind_addr(
        &self,
        protocol: IpNextHeaderProtocol,
        mut addr: SocketAddr,
        peer: Option<SocketAddr>,
        set_port: bool,
    ) -> io::Result<SocketAddr> {
        let mut guard = self.bind_addrs.lock();
        if set_port && addr.port() == 0 {
            let port_start: u16 = rand::rng().random_range(1..=65535);
            for i in 0..65535 {
                let port = port_start.wrapping_add(i);
                if port == 0 {
                    continue;
                }
                addr.set_port(port);
                let key = (protocol, addr, peer);
                if !guard.contains(&key) {
                    guard.insert(key);
                    return Ok(addr);
                }
            }
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "Address already in use"));
        }
        let key = (protocol, addr, peer);
        if guard.contains(&key) {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "Address already in use"));
        }
        guard.insert(key);
        Ok(addr)
    }
    fn remove_bind_addr(&self, protocol: IpNextHeaderProtocol, addr: SocketAddr, peer: Option<SocketAddr>) {
        let mut guard = self.bind_addrs.lock();
        guard.remove(&(protocol, addr, peer));
    }
}
#[derive(Debug)]
pub(crate) struct BindAddr {
    protocol: IpNextHeaderProtocol,
    pub(crate) addr: SocketAddr,
    peer: Option<SocketAddr>,
    inner: Arc<IpStackInner>,
}
impl BindAddr {
    pub(crate) fn set_peer(&mut self, local: SocketAddr, peer: SocketAddr) -> io::Result<()> {
        self.inner.remove_bind_addr(self.protocol, local, self.peer);
        self.inner.add_bind_addr(self.protocol, local, Some(peer), false)?;
        self.peer = Some(peer);
        Ok(())
    }
}
impl Drop for BindAddr {
    fn drop(&mut self) {
        self.inner.remove_bind_addr(self.protocol, self.addr, self.peer);
    }
}

#[cfg(feature = "global-ip-stack")]
lazy_static::lazy_static! {
    static ref IP_STACK: Mutex<Option<IpStack>> = Mutex::new(None);
}
#[cfg(feature = "global-ip-stack")]
impl IpStack {
    pub fn get() -> io::Result<IpStack> {
        if let Some(v) = IP_STACK.lock().clone() {
            Ok(v)
        } else {
            Err(io::Error::other("Not initialized IpStack"))
        }
    }
    pub fn release() {
        _ = IP_STACK.lock().take();
    }
    pub(crate) fn set(ip_stack: IpStack) {
        IP_STACK.lock().replace(ip_stack);
    }
}
