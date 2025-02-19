#![allow(unused, unused_variables)]
use pnet_packet::icmp::IcmpTypes;
use pnet_packet::icmpv6::Icmpv6Types;
use pnet_packet::Packet;
use std::net::IpAddr;
use std::sync::Arc;
use tcp_ip::icmp::{IcmpSocket, IcmpV6Socket};
use tcp_ip::ip::IpSocket;
use tcp_ip::{ip_stack, IpStackConfig, IpStackRecv, IpStackSend};
use tun_rs::{AsyncDevice, Configuration};

const MTU: u16 = 1420;

/// After starting the program,ping 10.0.0.0/24 (e.g. ping 10.0.0.2),
/// and you can receive a response from IcmpSocket
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    let mut config = Configuration::default();
    config
        .mtu(MTU)
        .address_with_prefix_multi(&[("CDCD:910A:2222:5498:8475:1111:3900:2025", 64), ("10.0.0.29", 24)])
        .up();
    let dev = tun_rs::create_as_async(&config)?;
    let dev = Arc::new(dev);
    let ip_stack_config = IpStackConfig {
        mtu: MTU,
        ..Default::default()
    };
    let (ip_stack_send, ip_stack_recv) = ip_stack(ip_stack_config)?;
    let icmp_socket = IcmpSocket::bind_all().await?;
    let icmp_v6_socket = IcmpV6Socket::bind_all().await?;

    let h1 = tokio::spawn(async {
        if let Err(e) = icmp_v4_recv(icmp_socket).await {
            log::error!("icmp {e:?}");
        }
    });
    let h1_1 = tokio::spawn(async {
        if let Err(e) = icmp_v6_recv(icmp_v6_socket).await {
            log::error!("icmpv6 {e:?}");
        }
    });
    let dev1 = dev.clone();
    let h2 = tokio::spawn(async {
        if let Err(e) = tun_to_ip_stack(dev1, ip_stack_send).await {
            log::error!("tun_to_ip_stack {e:?}");
        }
    });
    let h3 = tokio::spawn(async {
        if let Err(e) = ip_stack_to_tun(ip_stack_recv, dev).await {
            log::error!("ip_stack_to_tun {e:?}");
        }
    });
    let _ = tokio::try_join!(h1, h1_1, h2, h3);
    Ok(())
}

async fn icmp_v4_recv(icmp_socket: IcmpSocket) -> anyhow::Result<()> {
    let mut buf = [0; 65536];
    loop {
        let (len, src, dst) = icmp_socket.recv_from_to(&mut buf).await?;
        log::info!("src={src},dst={dst},len={len},buf={:?}", &buf[..len]);
        if let Some(mut packet) = pnet_packet::icmp::MutableIcmpPacket::new(&mut buf[..len]) {
            if packet.get_icmp_type() == IcmpTypes::EchoRequest {
                log::info!("icmpv4 {packet:?}");
                packet.set_icmp_type(IcmpTypes::EchoReply);
                let checksum = pnet_packet::icmp::checksum(&packet.to_immutable());
                packet.set_checksum(checksum);

                icmp_socket.send_from_to(packet.packet(), dst, src).await?;
            }
        }
    }
}
async fn icmp_v6_recv(icmp_socket: IcmpV6Socket) -> anyhow::Result<()> {
    let mut buf = [0; 65536];
    loop {
        let (len, src, dst) = icmp_socket.recv_from_to(&mut buf).await?;
        let src_ip = match src {
            IpAddr::V6(ip) => ip,
            IpAddr::V4(_) => unimplemented!(),
        };
        let dst_ip = match dst {
            IpAddr::V6(ip) => ip,
            IpAddr::V4(_) => unimplemented!(),
        };
        log::info!("src={src},dst={dst},len={len},buf={:?}", &buf[..len]);
        if let Some(mut packet) = pnet_packet::icmpv6::MutableIcmpv6Packet::new(&mut buf[..len]) {
            if packet.get_icmpv6_type() == Icmpv6Types::EchoRequest {
                log::info!("icmpv6 {packet:?}");
                packet.set_icmpv6_type(Icmpv6Types::EchoReply);
                let checksum = pnet_packet::icmpv6::checksum(&packet.to_immutable(), &dst_ip, &src_ip);
                packet.set_checksum(checksum);

                icmp_socket.send_from_to(packet.packet(), dst, src).await?;
            }
        }
    }
}

async fn tun_to_ip_stack(dev: Arc<AsyncDevice>, mut ip_stack_send: IpStackSend) -> anyhow::Result<()> {
    let mut buf = [0; MTU as usize];
    loop {
        let len = dev.recv(&mut buf).await?;
        if let Err(e) = ip_stack_send.send_ip_packet(&buf[..len]).await {
            log::error!("ip_stack_send.send_ip_packet e={e:?}")
        }
    }
}

async fn ip_stack_to_tun(mut ip_stack_recv: IpStackRecv, dev: Arc<AsyncDevice>) -> anyhow::Result<()> {
    let mut buf = [0; MTU as usize];
    loop {
        let len = ip_stack_recv.recv(&mut buf).await?;
        dev.send(&buf[..len]).await?;
    }
}
