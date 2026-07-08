#![cfg(not(feature = "global-ip-stack"))]

//! In-memory throughput benchmarks.
//!
//! Two `ip_stack` instances are connected back to back the same way the
//! `tcp_proxy` example is wired to a TUN device (batched `recv_ip_packet`,
//! MTU 1420), so the numbers roughly track the iperf3-through-TUN script
//! without needing root or a TUN device.
//!
//! Run with:
//! `cargo test --release --test throughput -- --ignored --nocapture`

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tcp_ip::tcp::{TcpListener, TcpStream};
use tcp_ip::{ip_stack, IpStack, IpStackConfig, IpStackRecv, IpStackSend};

const IP_A: &str = "10.0.0.1";
const IP_B: &str = "10.0.0.2";
const MTU: u16 = 1420;
const TOTAL_BYTES: usize = 64 * 1024 * 1024;

fn link(mut recv: IpStackRecv, send: IpStackSend) {
    tokio::spawn(async move {
        let mut bufs = Vec::with_capacity(128);
        let mut sizes = vec![0usize; 128];
        for _ in 0..128 {
            bufs.push(BytesMut::zeroed(MTU as usize));
        }
        while let Ok(num) = recv.recv_ip_packet(&mut bufs, &mut sizes).await {
            for i in 0..num {
                if send.send_ip_packet(&bufs[i][..sizes[i]]).await.is_err() {
                    return;
                }
            }
        }
    });
}

fn connect_stacks() -> (IpStack, IpStack) {
    let config = IpStackConfig::builder().mtu(MTU).build();
    let (stack_a, a_send, a_recv) = ip_stack(config).unwrap();
    let (stack_b, b_send, b_recv) = ip_stack(config).unwrap();
    link(a_recv, b_send);
    link(b_recv, a_send);
    (stack_a, stack_b)
}

/// Transfers `TOTAL_BYTES` from a writer task to a reader task and reports throughput.
async fn run_transfer(mut writer: TcpStream, mut reader: TcpStream, label: &str) {
    let write_task = tokio::spawn(async move {
        let chunk = vec![0x5au8; 64 * 1024];
        let mut sent = 0usize;
        while sent < TOTAL_BYTES {
            let n = chunk.len().min(TOTAL_BYTES - sent);
            writer.write_all(&chunk[..n]).await.unwrap();
            sent += n;
        }
        writer.shutdown().await.unwrap();
    });

    let start = Instant::now();
    let mut buf = vec![0u8; 64 * 1024];
    let mut received = 0usize;
    loop {
        let n = reader.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received += n;
    }
    let elapsed = start.elapsed();
    write_task.await.unwrap();
    assert_eq!(received, TOTAL_BYTES);

    let mib_s = TOTAL_BYTES as f64 / 1024.0 / 1024.0 / elapsed.as_secs_f64();
    let gbit_s = TOTAL_BYTES as f64 * 8.0 / 1e9 / elapsed.as_secs_f64();
    println!("{label}: {TOTAL_BYTES} bytes in {elapsed:?} => {mib_s:.1} MiB/s ({gbit_s:.2} Gbit/s)");
}

async fn setup_pair() -> (TcpStream, TcpStream) {
    let (stack_a, stack_b) = connect_stacks();
    let server_addr: SocketAddr = format!("{IP_B}:9000").parse().unwrap();
    let mut listener = TcpListener::bind(stack_b, server_addr).await.unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    let local: SocketAddr = format!("{IP_A}:0").parse().unwrap();
    let client = TcpStream::bind(stack_a, local).unwrap().connect_to(server_addr).await.unwrap();
    let server = accept.await.unwrap();
    (client, server)
}

/// Client sends, server receives — mirrors plain `iperf3 -c`.
#[tokio::test]
#[ignore]
async fn throughput_forward() {
    tokio::time::timeout(Duration::from_secs(300), async {
        let (client, server) = setup_pair().await;
        run_transfer(client, server, "forward (client->server, current_thread)").await;
    })
    .await
    .unwrap();
}

/// Server sends, client receives — mirrors `iperf3 -R`, sensitive to cwnd growth.
#[tokio::test]
#[ignore]
async fn throughput_reverse() {
    tokio::time::timeout(Duration::from_secs(300), async {
        let (client, server) = setup_pair().await;
        run_transfer(server, client, "reverse (server->client, current_thread)").await;
    })
    .await
    .unwrap();
}

/// Multi-thread runtime variant, matching how the tcp_proxy example runs.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn throughput_forward_multi_thread() {
    tokio::time::timeout(Duration::from_secs(300), async {
        let (client, server) = setup_pair().await;
        run_transfer(client, server, "forward (client->server, multi_thread)").await;
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn throughput_reverse_multi_thread() {
    tokio::time::timeout(Duration::from_secs(300), async {
        let (client, server) = setup_pair().await;
        run_transfer(server, client, "reverse (server->client, multi_thread)").await;
    })
    .await
    .unwrap();
}
