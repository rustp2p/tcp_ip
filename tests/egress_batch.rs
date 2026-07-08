#![cfg(not(feature = "global-ip-stack"))]

//! Tests for batched egress in `IpStackRecv::recv_ip_packet`: one call should
//! drain everything already queued, and packets that do not fit the caller's
//! buffers must be delivered on the next call instead of being lost.

use bytes::BytesMut;

use tcp_ip::udp::UdpSocket;
use tcp_ip::{ip_stack, IpStackConfig};

const MTU: usize = 1420;

#[tokio::test]
async fn batches_queued_packets_in_one_call() {
    let config = IpStackConfig::builder().mtu(MTU as u16).build();
    let (stack, _send, mut recv) = ip_stack(config).unwrap();
    let socket = UdpSocket::bind(stack, "10.0.0.1:2000").await.unwrap();
    for i in 0..10u8 {
        socket.send_to(&[i; 32], "10.0.0.2:2001").await.unwrap();
    }

    let mut bufs: Vec<BytesMut> = (0..128).map(|_| BytesMut::zeroed(MTU)).collect();
    let mut sizes = vec![0usize; 128];
    let num = recv.recv_ip_packet(&mut bufs, &mut sizes).await.unwrap();
    assert_eq!(num, 10, "queued datagrams should be drained in one call");
    for i in 0..num {
        // 20 bytes IPv4 header + 8 bytes UDP header + payload
        assert_eq!(sizes[i], 20 + 8 + 32);
        assert_eq!(bufs[i][28], i as u8);
    }
}

#[tokio::test]
async fn packet_not_fitting_is_delivered_next_call() {
    let config = IpStackConfig::builder().mtu(MTU as u16).build();
    let (stack, _send, mut recv) = ip_stack(config).unwrap();
    let socket = UdpSocket::bind(stack, "10.0.0.1:2000").await.unwrap();
    // 4000-byte datagram fragments into 3 IP packets at MTU 1420.
    socket.send_to(&[0xaa; 4000], "10.0.0.2:2001").await.unwrap();
    for i in 0..2u8 {
        socket.send_to(&[i; 32], "10.0.0.2:2001").await.unwrap();
    }
    socket.send_to(&[0xbb; 4000], "10.0.0.2:2001").await.unwrap();

    // Room for 4 packets: the second large datagram (3 fragments) cannot fit
    // after the first 5 packets and must be stashed, not lost.
    let mut bufs: Vec<BytesMut> = (0..4).map(|_| BytesMut::zeroed(MTU)).collect();
    let mut sizes = vec![0usize; 4];
    let mut total = 0;
    let mut received_bytes = 0usize;
    while total < 8 {
        let num = recv.recv_ip_packet(&mut bufs, &mut sizes).await.unwrap();
        assert!(num > 0 && num <= 4);
        total += num;
        received_bytes += sizes[..num].iter().sum::<usize>();
    }
    assert_eq!(total, 8, "3 + 1 + 1 + 3 IP packets, none lost");
    // 2 datagrams of 4000 bytes -> 3 fragments each: headers = 2*(3*20 + 8);
    // 2 small datagrams: 2*(20 + 8 + 32)
    assert_eq!(received_bytes, 2 * (4000 + 3 * 20 + 8) + 2 * (20 + 8 + 32));
}
