use bytes::BytesMut;
use packet::{icmp, Builder, Packet as IcmpPacket};
use std::sync::Arc;
use tcp_ip::icmp::IcmpSocket;
use tcp_ip::ip_stack::{ip_stack, IpStackConfig, IpStackRecv, IpStackSend};
use tun_rs::{AsyncDevice, Configuration};

const MTU: u16 = 1420;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    let mut config = Configuration::default();

    config.mtu(MTU).address_with_prefix((10, 0, 0, 29), 24).up();
    let dev = tun_rs::create_as_async(&config)?;
    let dev = Arc::new(dev);
    let mut ip_stack_config = IpStackConfig::default();
    ip_stack_config.mtu = MTU;
    let (ip_stack, ip_stack_send, ip_stack_recv) = ip_stack(ip_stack_config)?;
    let icmp_socket = IcmpSocket::bind_all(ip_stack.clone()).await?;

    let h1 = tokio::spawn(async {
        if let Err(e) = icmp_recv(icmp_socket).await {
            log::error!("udp {e:?}");
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
    let _ = tokio::try_join!(h1, h2, h3);
    Ok(())
}

async fn icmp_recv(icmp_socket: IcmpSocket) -> anyhow::Result<()> {
    let mut buf = [0; 65536];
    loop {
        let (len, src, dst) = icmp_socket.recv_from_to(&mut buf).await?;
        log::info!("src={src},dst={dst},len={len},buf={:?}", &buf[..len]);
        if let Ok(packet) = icmp::Packet::new(&buf[..len]) {
            if let Ok(packet) = packet.echo() {
                let reply = icmp::Builder::default()
                    .echo()?
                    .reply()?
                    .identifier(packet.identifier())?
                    .sequence(packet.sequence())?
                    .payload(packet.payload())?
                    .build()?;
                icmp_socket.send_from_to(&reply, dst, src).await?;
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
    let mut bufs = Vec::with_capacity(128);
    let mut sizes = vec![0; 128];
    for _ in 0..128 {
        bufs.push(BytesMut::zeroed(MTU as usize))
    }
    loop {
        let num = ip_stack_recv.recv_ip_packet(&mut bufs, &mut sizes).await?;
        log::debug!("ip_stack_to_tun num={num}");
        for index in 0..num {
            let buf = &bufs[index];
            let len = sizes[index];
            dev.send(&buf[..len]).await?;
        }
    }
}
