#![allow(unused, unused_variables)]
use std::sync::Arc;

use packet::{icmp, Builder, Packet as IcmpPacket};
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::Packet;
use tun_rs::{AsyncDevice, Configuration};

use tcp_ip::icmp::IcmpSocket;
use tcp_ip::ip::Ipv4Socket;
use tcp_ip::ip_stack::{ip_stack, IpStackConfig, IpStackRecv, IpStackSend};

const MTU: u16 = 1420;

/// Handles all IPv4 upper-layer protocols without requiring the user to consider IP fragmentation.
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    let mut config = Configuration::default();

    config.mtu(MTU).address_with_prefix((10, 0, 0, 29), 24).up();
    let dev = tun_rs::create_as_async(&config)?;
    let dev = Arc::new(dev);
    let ip_stack_config = IpStackConfig {
        mtu: MTU,
        ..Default::default()
    };
    let (ip_stack, ip_stack_send, ip_stack_recv) = ip_stack(ip_stack_config)?;
    // None means receiving all protocols.
    let ip_socket = Ipv4Socket::bind_all(None, ip_stack.clone()).await?;

    let h1 = tokio::spawn(async {
        if let Err(e) = ip_recv(ip_socket).await {
            log::error!("ip packet {e:?}");
        }
    });
    let dev1 = dev.clone();
    let h2 = tokio::spawn(async {
        // Reads packet from TUN and sends to stack.
        if let Err(e) = tun_to_ip_stack(dev1, ip_stack_send).await {
            log::error!("tun_to_ip_stack {e:?}");
        }
    });
    let h3 = tokio::spawn(async {
        // Reads packet from stack and sends to TUN.
        if let Err(e) = ip_stack_to_tun(ip_stack_recv, dev).await {
            log::error!("ip_stack_to_tun {e:?}");
        }
    });
    let _ = tokio::try_join!(h1, h2, h3);
    Ok(())
}

async fn ip_recv(ip_socket: Ipv4Socket) -> anyhow::Result<()> {
    let mut buf = [0; 65536];
    loop {
        let (len, p, src, dst) = ip_socket.recv_protocol_from_to(&mut buf).await?;
        // The read and write operations of Ipv4Socket do not include the IP header.
        log::info!("src={src},dst={dst},len={len},buf={:?}", &buf[..len]);
        match p {
            IpNextHeaderProtocols::Icmp => {
                if let Ok(packet) = icmp::Packet::new(&buf[..len]) {
                    if let Ok(packet) = packet.echo() {
                        let reply = icmp::Builder::default()
                            .echo()?
                            .reply()?
                            .identifier(packet.identifier())?
                            .sequence(packet.sequence())?
                            .payload(packet.payload())?
                            .build()?;
                        ip_socket
                            .send_protocol_from_to(&reply, IpNextHeaderProtocols::Icmp, dst, src)
                            .await?;
                    }
                }
            }
            IpNextHeaderProtocols::Udp => {
                let udp_packet = pnet_packet::udp::UdpPacket::new(&buf[..len]).unwrap();
                // When using this socket to send UDP packets, you need to calculate the UDP checksum yourself.
                log::info!("recv udp {:?}", std::str::from_utf8(udp_packet.payload()));
            }
            _ => {}
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
        log::debug!("ip_stack_to_tun num={len}");
        dev.send(&buf[..len]).await?;
    }
}
