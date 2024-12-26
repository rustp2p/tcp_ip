#![allow(unused, unused_variables)]
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use pnet_packet::Packet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun_rs::{AsyncDevice, Configuration};

use tcp_ip::ip_stack::{ip_stack, IpStackConfig, IpStackRecv, IpStackSend};

const MTU: u16 = 1420;
/// This example demonstrates how to use a TCP active connection to a userspace TCP/IP protocol stack,
/// which can convert TCP data into IP packets.
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    let mut config = Configuration::default();
    let local_ip = Ipv4Addr::new(10, 0, 0, 29);
    config.mtu(MTU).address_with_prefix(local_ip, 24).up();
    let dev = tun_rs::create_as_async(&config)?;
    let dev = Arc::new(dev);
    let ip_stack_config = IpStackConfig {
        mtu: MTU,
        ..Default::default()
    };
    let (ip_stack, ip_stack_send, ip_stack_recv) = ip_stack(ip_stack_config)?;
    let dev1 = dev.clone();
    tokio::spawn(async {
        if let Err(e) = tun_to_ip_stack(dev1, ip_stack_send).await {
            log::error!("tun_to_ip_stack {e:?}");
        }
    });
    tokio::spawn(async {
        if let Err(e) = ip_stack_to_tun(ip_stack_recv, dev).await {
            log::error!("ip_stack_to_tun {e:?}");
        }
    });
    let listen_addr = SocketAddrV4::new(local_ip, 18888);
    // Waiting for the Tun network card to take effect.
    // Otherwise, it cannot be bound to the IP address
    tokio::time::sleep(Duration::from_secs(10)).await;
    let tokio_tcp_listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tokio::spawn(async move {
        log::info!("tokio_tcp_listener accept {:?}", tokio_tcp_listener.local_addr());
        loop {
            let (mut tokio_tcp_stream, addr) = match tokio_tcp_listener.accept().await {
                Ok(rs) => rs,
                Err(e) => {
                    log::error!("tokio_tcp_listener accept {e:?}");
                    break;
                }
            };
            log::info!("tokio_tcp_stream addr:{addr}");
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                match tokio_tcp_stream.read(&mut buf).await {
                    Ok(len) => {
                        log::info!("tokio_tcp_stream read len={len},buf={:?}", &buf[..len]);
                        if let Err(e) = tokio_tcp_stream.write(b"hello").await {
                            log::error!("tokio_tcp_stream write {e:?}");
                        }
                    }
                    Err(e) => {
                        log::error!("tokio_tcp_stream read {e:?}");
                    }
                }
            });
        }
    });
    let peer_addr = SocketAddrV4::new(local_ip, 18888);
    log::info!("tcp_ip_stream connecting. addr:{peer_addr}");
    let mut tcp_ip_stream = tcp_ip::tcp::TcpStream::connect(ip_stack.clone(), "10.0.0.2:18889".parse().unwrap(), peer_addr.into()).await?;
    log::info!("tcp_ip_stream connection successful. addr:{peer_addr}");
    tcp_ip_stream.write_all(b"hi").await?;
    let mut buf = [0; 1024];
    let len = tcp_ip_stream.read(&mut buf).await?;
    log::info!("tcp_ip_stream read len={len},buf={:?}", &buf[..len]);
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
