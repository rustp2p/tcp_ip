# tcp_ip

User-space TCP/IP stack

## Features

#### IPv4

- IPv4 fragmentation and reassembly is supported.
- IPv4 options are not supported and are silently ignored.

#### IPv6

- In development, currently does not support any extended protocols.

#### UDP

Use UdpSocket. Supported over IPv4 and IPv6.

#### ICMPv4 & ICMPv6

Use IcmpSocket or IcmpV6Socket. The user needs to handle the ICMP header themselves and calculate the checksum.

#### TCP

Use TcpListener and TcpStream. Supported over IPv4 and IPv6.

- MSS is negotiated
- Window scaling is negotiated.
- Reassembly of out-of-order segments is supported
- The timeout waiting time is fixed and can be configured
- Selective acknowledgements permitted. (Proactively ACK the need for improvement)

#### Other

Using IpSocket to send and receive packets of other protocols.(Handles all IP upper-layer protocols without requiring
the user to consider IP fragmentation.)

## example

- [tcp](https://github.com/rustp2p/tcp_ip/blob/main/examples/tcp.rs)
- [udp](https://github.com/rustp2p/tcp_ip/blob/main/examples/udp.rs)
- [icmp](https://github.com/rustp2p/tcp_ip/blob/main/examples/icmp.rs)
- [ipv4_ipv6](https://github.com/rustp2p/tcp_ip/blob/main/examples/ipv4_ipv6.rs)
- [proxy](https://github.com/rustp2p/tcp_ip/blob/main/examples/tcp_proxy.rs)
- [tcp_connect](https://github.com/rustp2p/tcp_ip/blob/main/examples/tcp_connect.rs)

## iperf test

### LAN Speed Test

![image](https://github.com/user-attachments/assets/135c2ff9-9515-46c2-9439-e035f3422d54)

### Example：[Proxy](https://github.com/rustp2p/tcp_ip/blob/main/examples/tcp_proxy.rs)-Windows

![image](https://github.com/user-attachments/assets/9a56de87-2e89-4a42-9587-8f1923935739)

### Example: [Proxy](https://github.com/rustp2p/tcp_ip/blob/main/examples/tcp_proxy.rs)-Linux

![image](https://github.com/user-attachments/assets/23d7863a-475a-4602-b56a-a1444cfa155d)

