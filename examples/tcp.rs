#![allow(unused, unused_variables)]
use std::sync::Arc;

use bytes::BytesMut;
use pnet_packet::Packet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun_rs::{AsyncDevice, Configuration};

use tcp_ip::tcp::TcpListener;
use tcp_ip::{ip_stack, IpStackConfig, IpStackRecv, IpStackSend};

const MTU: u16 = 1420;

/// After starting, use a TCP connection to any port in the 10.0.0.0/24 subnet (e.g., telnet 10.0.0.2 8080).
/// Sending data will receive a response.
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
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
    let (ip_stack, ip_stack_send, ip_stack_recv) = ip_stack(ip_stack_config)?;
    let mut tcp_listener = TcpListener::bind_all(ip_stack.clone()).await?;

    let h1 = tokio::spawn(async move {
        loop {
            let (mut tcp_stream, addr) = match tcp_listener.accept().await {
                Ok(rs) => rs,
                Err(e) => {
                    log::error!("tcp_listener accept {e:?}");
                    break;
                }
            };
            log::info!("tcp_stream addr:{addr}");
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                loop {
                    match tcp_stream.read(&mut buf).await {
                        Ok(len) => {
                            log::info!("tcp_stream read len={len},buf={:?}", &buf[..len]);
                            if let Err(e) = tcp_stream.write(&buf[..len]).await {
                                log::error!("tcp_stream write {e:?}");
                                break;
                            }
                        }
                        Err(e) => {
                            log::error!("tcp_stream read {e:?}");
                            break;
                        }
                    }
                }
            });
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
    let _ = tokio::try_join!(h1, h2, h3,);
    Ok(())
}

async fn tun_to_ip_stack(dev: Arc<AsyncDevice>, mut ip_stack_send: IpStackSend) -> anyhow::Result<()> {
    let mut buf = [0; MTU as usize];
    loop {
        let len = dev.recv(&mut buf).await?;
        let packet = pnet_packet::ipv4::Ipv4Packet::new(&buf[..len]).unwrap();
        if packet.get_next_level_protocol() == pnet_packet::ip::IpNextHeaderProtocols::Tcp {
            // log::debug!("tun_to_ip_stack {packet:?}");
            let tcp_packet = pnet_packet::tcp::TcpPacket::new(packet.payload()).unwrap();
            log::debug!("tun_to_ip_stack tcp_packet={tcp_packet:?} payload={:?}", tcp_packet.payload());
        }

        if let Err(e) = ip_stack_send.send_ip_packet(&buf[..len]).await {
            log::error!("ip_stack_send.send_ip_packet e={e:?}")
        }
    }
}

async fn ip_stack_to_tun(mut ip_stack_recv: IpStackRecv, dev: Arc<AsyncDevice>) -> anyhow::Result<()> {
    let mut bufs = Vec::with_capacity(128);
    let mut sizes = vec![0; 128];
    for _ in 0..128 {
        bufs.push(BytesMut::zeroed(MTU as usize))
    }
    loop {
        let num = ip_stack_recv.recv_ip_packet(&mut bufs, &mut sizes).await?;
        // log::debug!("ip_stack_to_tun num={num}");
        for index in 0..num {
            let buf = &bufs[index];
            let len = sizes[index];
            let packet = pnet_packet::ipv4::Ipv4Packet::new(&buf[..len]).unwrap();
            // log::debug!("ip_stack_to_tun {packet:?}");
            if packet.get_next_level_protocol() == pnet_packet::ip::IpNextHeaderProtocols::Tcp {
                let tcp_packet = pnet_packet::tcp::TcpPacket::new(packet.payload()).unwrap();
                log::debug!("ip_stack_to_tun tcp_packet={tcp_packet:?} payload={:?}", tcp_packet.payload());
            }

            dev.send(&buf[..len]).await?;
        }
    }
}
