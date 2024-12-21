use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use clap::Parser;
use pnet_packet::Packet;
use tun_rs::{AsyncDevice, Configuration};

use tcp_ip::ip_stack::{ip_stack, IpStackConfig, IpStackRecv, IpStackSend};
use tcp_ip::tcp::TcpListener;

const MTU: u16 = 1420;
#[derive(Parser)]
pub struct Args {
    #[arg(short, long)]
    server_addr: SocketAddr,
}
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let server_addr = args.server_addr;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let mut config = Configuration::default();

    config.mtu(MTU).address_with_prefix((10, 0, 0, 29), 24).up();
    let dev = tun_rs::create_as_async(&config)?;
    let dev = Arc::new(dev);
    let mut ip_stack_config = IpStackConfig::default();
    ip_stack_config.mtu = MTU;
    let (ip_stack, ip_stack_send, ip_stack_recv) = ip_stack(ip_stack_config)?;
    let mut tcp_listener = TcpListener::bind_all(ip_stack.clone()).await?;

    let h1 = tokio::spawn(async move {
        loop {
            let (tcp_stream, addr) = match tcp_listener.accept().await {
                Ok(rs) => rs,
                Err(e) => {
                    log::error!("tcp_listener accept {e:?}");
                    break;
                }
            };
            log::info!("tcp_stream addr:{addr}");
            let server_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();

            tokio::spawn(async move {
                let (mut client_write, mut client_read) = tcp_stream.split();
                let (mut server_read, mut server_write) = server_stream.into_split();
                let h1 = tokio::io::copy(&mut client_read, &mut server_write);
                let h2 = tokio::io::copy(&mut server_read, &mut client_write);
                let rs = tokio::join!(h1, h2);
                log::info!("copy rs:{rs:?}");
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
            let tcp_packet = pnet_packet::tcp::TcpPacket::new(packet.payload()).unwrap();
            log::debug!("tun_to_ip_stack tcp_packet={tcp_packet:?}");
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
                log::debug!("ip_stack_to_tun tcp_packet={tcp_packet:?}");
            }

            dev.send(&buf[..len]).await?;
        }
    }
}
