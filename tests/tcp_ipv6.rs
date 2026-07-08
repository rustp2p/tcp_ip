#![cfg(not(feature = "global-ip-stack"))]

//! End-to-end IPv6 tests.
//!
//! Two independent `ip_stack` instances are connected back to back in memory:
//! every IP packet read from one stack's `IpStackRecv` is written into the
//! other stack's `IpStackSend`. A lossy variant of the link drops and reorders
//! packets to exercise retransmission, SACK and the out-of-order queue, and a
//! reversed variant delivers each burst of packets backwards so IPv6 fragments
//! arrive before the first fragment of their packet.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tcp_ip::tcp::{TcpListener, TcpStream};
use tcp_ip::udp::UdpSocket;
use tcp_ip::{ip_stack, IpStack, IpStackConfig, IpStackRecv, IpStackSend};

const IP_A: &str = "fd00::1";
const IP_B: &str = "fd00::2";

fn perfect_link(mut recv: IpStackRecv, send: IpStackSend) {
    tokio::spawn(async move {
        let mut buf = [0u8; u16::MAX as usize];
        while let Ok(len) = recv.recv(&mut buf).await {
            if send.send_ip_packet(&buf[..len]).await.is_err() {
                break;
            }
        }
    });
}

/// A link that deterministically drops one packet in seven and delays one
/// packet in five until after its successor (reordering).
fn lossy_link(mut recv: IpStackRecv, send: IpStackSend) {
    tokio::spawn(async move {
        let mut buf = [0u8; u16::MAX as usize];
        let mut counter = 0u64;
        let mut held: Option<Vec<u8>> = None;
        loop {
            let len = match recv.recv(&mut buf).await {
                Ok(len) => len,
                Err(_) => break,
            };
            counter += 1;
            if counter % 7 == 3 {
                // drop
                continue;
            }
            if counter.is_multiple_of(5) && held.is_none() {
                // hold this packet back to reorder it with the next one
                held = Some(buf[..len].to_vec());
                continue;
            }
            if send.send_ip_packet(&buf[..len]).await.is_err() {
                break;
            }
            if let Some(delayed) = held.take() {
                if send.send_ip_packet(&delayed).await.is_err() {
                    break;
                }
            }
        }
    });
}

/// A link that delivers every burst of packets in reverse order, so the
/// fragments of a fragmented packet arrive before their first fragment.
fn reversed_link(mut recv: IpStackRecv, send: IpStackSend) {
    tokio::spawn(async move {
        let mut bufs = vec![vec![0u8; u16::MAX as usize]; 128];
        let mut sizes = vec![0usize; 128];
        loop {
            let num = match recv.recv_ip_packet(&mut bufs, &mut sizes).await {
                Ok(num) => num,
                Err(_) => break,
            };
            for i in (0..num).rev() {
                if send.send_ip_packet(&bufs[i][..sizes[i]]).await.is_err() {
                    return;
                }
            }
        }
    });
}

/// Creates two stacks (A and B) whose IP packets are piped into each other.
fn connect_stacks(config: IpStackConfig, link: fn(IpStackRecv, IpStackSend)) -> (IpStack, IpStack) {
    let (stack_a, a_send, a_recv) = ip_stack(config).unwrap();
    let (stack_b, b_send, b_recv) = ip_stack(config).unwrap();
    link(a_recv, b_send);
    link(b_recv, a_send);
    (stack_a, stack_b)
}

fn test_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

async fn read_to_end(stream: &mut (impl AsyncReadExt + Unpin)) -> Vec<u8> {
    let mut received = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    received
}

async fn client_connect(stack: IpStack, server_addr: SocketAddr) -> TcpStream {
    let local: SocketAddr = format!("[{IP_A}]:0").parse().unwrap();
    TcpStream::bind(stack, local).unwrap().connect_to(server_addr).await.unwrap()
}

#[tokio::test]
async fn basic_connect_and_echo() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (stack_a, stack_b) = connect_stacks(IpStackConfig::default(), perfect_link);
        let server_addr: SocketAddr = format!("[{IP_B}]:8080").parse().unwrap();
        let mut listener = TcpListener::bind(stack_b, server_addr).await.unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await.unwrap();
            }
            stream.shutdown().await.unwrap();
        });

        let mut client = client_connect(stack_a, server_addr).await;
        let msg = b"hello tcp_ip";
        client.write_all(msg).await.unwrap();
        let mut echoed = [0u8; 12];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, msg);

        client.shutdown().await.unwrap();
        let mut end = [0u8; 1];
        assert_eq!(client.read(&mut end).await.unwrap(), 0, "expected EOF after server close");
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn large_transfer() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (stack_a, stack_b) = connect_stacks(IpStackConfig::default(), perfect_link);
        let server_addr: SocketAddr = format!("[{IP_B}]:8081").parse().unwrap();
        let mut listener = TcpListener::bind(stack_b, server_addr).await.unwrap();

        let data = test_data(4 * 1024 * 1024);
        let expected = data.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let received = read_to_end(&mut stream).await;
            assert_eq!(received.len(), expected.len());
            assert!(received == expected, "received data corrupted");
            stream.write_all(b"OK").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut client = client_connect(stack_a, server_addr).await;
        client.write_all(&data).await.unwrap();
        client.shutdown().await.unwrap();

        let response = read_to_end(&mut client).await;
        assert_eq!(&response, b"OK");
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn large_transfer_lossy_and_reordered() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut config = IpStackConfig::default();
        config.tcp_config.retransmission_timeout = Duration::from_millis(50);
        config.tcp_config.time_wait_timeout = Duration::from_secs(1);
        let (stack_a, stack_b) = connect_stacks(config, lossy_link);
        let server_addr: SocketAddr = format!("[{IP_B}]:8082").parse().unwrap();
        let mut listener = TcpListener::bind(stack_b, server_addr).await.unwrap();

        let data = test_data(512 * 1024);
        let expected = data.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let received = read_to_end(&mut stream).await;
            assert_eq!(received.len(), expected.len());
            assert!(received == expected, "received data corrupted");
            stream.write_all(b"OK").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut client = client_connect(stack_a, server_addr).await;
        client.write_all(&data).await.unwrap();
        client.shutdown().await.unwrap();

        let response = read_to_end(&mut client).await;
        assert_eq!(&response, b"OK");
        server.await.unwrap();
    })
    .await
    .unwrap();
}

/// The receiver stops reading long enough for its window to close, then
/// resumes. All written bytes must still arrive intact (no data may be lost
/// while the send side is blocked on a zero window).
#[tokio::test]
async fn zero_window_no_data_loss() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut config = IpStackConfig::default();
        config.tcp_config.rcv_wnd = 2048;
        config.tcp_config.window_shift_cnt = 0;
        config.tcp_config.retransmission_timeout = Duration::from_millis(100);
        config.tcp_channel_size = 4;
        let (stack_a, stack_b) = connect_stacks(config, perfect_link);
        let server_addr: SocketAddr = format!("[{IP_B}]:8083").parse().unwrap();
        let mut listener = TcpListener::bind(stack_b, server_addr).await.unwrap();

        let data = test_data(256 * 1024);
        let expected = data.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Do not read anything: the advertised window shrinks to zero and
            // the client's writes must stall instead of losing data.
            tokio::time::sleep(Duration::from_secs(2)).await;
            let received = read_to_end(&mut stream).await;
            assert_eq!(received.len(), expected.len());
            assert!(received == expected, "received data corrupted");
            stream.shutdown().await.unwrap();
        });

        let mut client = client_connect(stack_a, server_addr).await;
        client.write_all(&data).await.unwrap();
        client.shutdown().await.unwrap();
        read_to_end(&mut client).await;
        server.await.unwrap();
    })
    .await
    .unwrap();
}

/// The client drops its read half before the server sends its FIN. The
/// connection must still tear down completely on both sides (the FIN must be
/// processed and acknowledged even though the receive window is zero).
#[tokio::test]
async fn read_half_dropped_connection_still_closes() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut config = IpStackConfig::default();
        config.tcp_config.time_wait_timeout = Duration::from_millis(500);
        let (stack_a, stack_b) = connect_stacks(config, perfect_link);
        let server_addr: SocketAddr = format!("[{IP_B}]:8084").parse().unwrap();
        let mut listener = TcpListener::bind(stack_b.clone(), server_addr).await.unwrap();

        let data = test_data(16 * 1024);
        let expected = data.clone();

        let server = tokio::spawn(async move {
            let (mut stream, peer_addr) = listener.accept().await.unwrap();
            let received = read_to_end(&mut stream).await;
            assert!(received == expected, "received data corrupted");
            // Dropping the stream sends our FIN to a peer whose read half is gone.
            drop(stream);
            peer_addr
        });

        let client = client_connect(stack_a.clone(), server_addr).await;
        let client_addr = client.local_addr().unwrap();
        let (mut write_half, read_half) = client.split().unwrap();
        drop(read_half);
        write_half.write_all(&data).await.unwrap();
        write_half.shutdown().await.unwrap();

        let peer_addr = server.await.unwrap();
        assert_eq!(peer_addr, client_addr);

        // Both stacks must eventually remove the connection entry, which only
        // happens when their stream tasks finish.
        loop {
            let a_alive = stack_a.has_tcp_connection(client_addr, server_addr).unwrap();
            let b_alive = stack_b.has_tcp_connection(server_addr, client_addr).unwrap();
            if !a_alive && !b_alive {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

/// A datagram larger than the MTU must be split into IPv6 fragments on the
/// way out and reassembled by the receiving stack, in both directions.
#[tokio::test]
async fn udp_fragmentation_round_trip() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (stack_a, stack_b) = connect_stacks(IpStackConfig::default(), perfect_link);
        let addr_a: SocketAddr = format!("[{IP_A}]:9000").parse().unwrap();
        let addr_b: SocketAddr = format!("[{IP_B}]:9001").parse().unwrap();
        let socket_a = UdpSocket::bind(stack_a, addr_a).await.unwrap();
        let socket_b = UdpSocket::bind(stack_b, addr_b).await.unwrap();

        let data = test_data(8000);
        socket_a.send_to(&data, addr_b).await.unwrap();

        let mut buf = vec![0u8; u16::MAX as usize];
        let (len, from) = socket_b.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, addr_a);
        assert_eq!(&buf[..len], &data[..], "reassembled datagram corrupted");

        // echo it back
        socket_b.send_to(&buf[..len], from).await.unwrap();
        let (len, from) = socket_a.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, addr_b);
        assert_eq!(&buf[..len], &data[..], "echoed datagram corrupted");
    })
    .await
    .unwrap();
}

/// Fragments delivered in reverse order force the receiving stack to buffer
/// fragments whose network tuple is still unknown until the first fragment
/// (the one carrying the UDP header) arrives.
#[tokio::test]
async fn udp_fragmentation_out_of_order() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (stack_a, stack_b) = connect_stacks(IpStackConfig::default(), reversed_link);
        let addr_a: SocketAddr = format!("[{IP_A}]:9002").parse().unwrap();
        let addr_b: SocketAddr = format!("[{IP_B}]:9003").parse().unwrap();
        let socket_a = UdpSocket::bind(stack_a, addr_a).await.unwrap();
        let socket_b = UdpSocket::bind(stack_b, addr_b).await.unwrap();

        let data = test_data(8000);
        socket_a.send_to(&data, addr_b).await.unwrap();

        let mut buf = vec![0u8; u16::MAX as usize];
        let (len, from) = socket_b.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, addr_a);
        assert_eq!(&buf[..len], &data[..], "reassembled datagram corrupted");
    })
    .await
    .unwrap();
}

/// Every packet emitted for an oversized payload must fit within the MTU and
/// carry a well-formed fragment header chain.
#[tokio::test]
async fn ipv6_egress_fragments_respect_mtu() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let config = IpStackConfig::default();
        let mtu = config.mtu as usize;
        let (stack, _send, mut recv) = ip_stack(config).unwrap();
        let addr_a: SocketAddr = format!("[{IP_A}]:9004").parse().unwrap();
        let addr_b: SocketAddr = format!("[{IP_B}]:9005").parse().unwrap();
        let socket = UdpSocket::bind(stack, addr_a).await.unwrap();

        let data = test_data(8000);
        socket.send_to(&data, addr_b).await.unwrap();

        let mut bufs = vec![vec![0u8; u16::MAX as usize]; 128];
        let mut sizes = vec![0usize; 128];
        let num = recv.recv_ip_packet(&mut bufs, &mut sizes).await.unwrap();
        assert!(num > 1, "an oversized payload must be fragmented");
        let mut reassembled = Vec::new();
        for i in 0..num {
            let packet = &bufs[i][..sizes[i]];
            assert!(packet.len() <= mtu, "fragment {i} exceeds the mtu: {}", packet.len());
            assert_eq!(packet[0] >> 4, 6);
            // Fixed header: payload length, next header = Fragment (44).
            let payload_length = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            assert_eq!(packet.len(), 40 + payload_length);
            assert_eq!(packet[6], 44);
            // Fragment header: next header = UDP (17), correct offset and M flag.
            let fragment_header = &packet[40..48];
            assert_eq!(fragment_header[0], 17);
            let offset_flags = u16::from_be_bytes([fragment_header[2], fragment_header[3]]);
            assert_eq!((offset_flags & !0b111) as usize, reassembled.len());
            let more_fragments = offset_flags & 0b1 == 0b1;
            assert_eq!(more_fragments, i != num - 1);
            reassembled.extend_from_slice(&packet[48..]);
        }
        // The reassembled payload is the UDP header plus the datagram.
        assert_eq!(reassembled.len(), 8 + data.len());
        assert_eq!(&reassembled[8..], &data[..]);
    })
    .await
    .unwrap();
}
