#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("packetdrill_harness is only supported on Linux");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{anyhow, bail, Context, Result};
    use clap::{Parser, Subcommand};
    use std::ffi::CString;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::net::SocketAddr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;
    use tcp_ip::tcp::{TcpConfig, TcpListener, TcpStream};
    use tcp_ip::{ip_stack, IpStackConfig, IpStackRecv, IpStackSend};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::{mpsc, Mutex, Notify, OwnedMutexGuard};

    const ETH_P_ALL: u16 = 0x0003;
    const PACKET_OUTGOING: u8 = 4;

    #[derive(Parser)]
    #[command(name = "packetdrill_harness")]
    #[command(about = "packetdrill adapter for the tcp_ip userspace stack")]
    struct Args {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Subcommand)]
    enum Command {
        /// Run the packet adapter and control server.
        Daemon {
            #[arg(long, default_value = "tun0")]
            interface: String,
            #[arg(long)]
            socket: PathBuf,
            #[arg(long)]
            ack_delay_ms: Option<u64>,
        },
        /// Start a passive listener. The accepted stream becomes the current stream.
        Listen {
            #[arg(long)]
            socket: PathBuf,
            address: SocketAddr,
        },
        /// Start an active connection without blocking the packetdrill timeline.
        Connect {
            #[arg(long)]
            socket: PathBuf,
            local: SocketAddr,
            peer: SocketAddr,
        },
        /// Write bytes encoded as hexadecimal to the current stream.
        WriteHex {
            #[arg(long)]
            socket: PathBuf,
            hex: String,
        },
        /// Write zero bytes, matching packetdrill's generated payload.
        WriteZero {
            #[arg(long)]
            socket: PathBuf,
            length: usize,
        },
        /// Send FIN on the current stream's write half.
        ShutdownWrite {
            #[arg(long)]
            socket: PathBuf,
        },
        /// Read and compare exactly the supplied hexadecimal bytes.
        ExpectReadHex {
            #[arg(long)]
            socket: PathBuf,
            hex: String,
            #[arg(long, default_value_t = 1000)]
            timeout_ms: u64,
        },
        /// Read the requested number of bytes and require zero payload.
        ExpectReadZero {
            #[arg(long)]
            socket: PathBuf,
            length: usize,
            #[arg(long, default_value_t = 1000)]
            timeout_ms: u64,
        },
        /// Require EOF from the current stream.
        ExpectEof {
            #[arg(long)]
            socket: PathBuf,
            #[arg(long, default_value_t = 1000)]
            timeout_ms: u64,
        },
        /// Print whether a stream is pending, connected, or failed.
        Status {
            #[arg(long)]
            socket: PathBuf,
        },
        /// Shut down the daemon.
        Stop {
            #[arg(long)]
            socket: PathBuf,
        },
    }

    #[derive(Default)]
    struct AppState {
        stream: Option<TcpStream>,
        pending: bool,
        last_error: Option<String>,
    }

    #[cfg(not(feature = "global-ip-stack"))]
    type StackHandle = tcp_ip::IpStack;
    #[cfg(feature = "global-ip-stack")]
    #[derive(Clone, Copy)]
    struct StackHandle;

    #[cfg(not(feature = "global-ip-stack"))]
    fn clone_stack(stack: &StackHandle) -> StackHandle {
        stack.clone()
    }

    #[cfg(feature = "global-ip-stack")]
    fn clone_stack(_stack: &StackHandle) -> StackHandle {
        StackHandle
    }

    struct PacketDevice {
        recv_fd: OwnedFd,
        sender: PacketSender,
    }

    impl PacketDevice {
        fn open(interface: &str) -> Result<Self> {
            let name = CString::new(interface).context("interface contains a NUL byte")?;
            let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) } as i32;
            if ifindex == 0 {
                return Err(io::Error::last_os_error()).context("if_nametoindex");
            }

            let protocol = ETH_P_ALL.to_be() as i32;
            // Match packetdrill/tcpdump and use SOCK_RAW. TUN devices have no
            // link-layer header, so the bytes still begin with the IP header.
            let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocol) };
            if fd < 0 {
                return Err(io::Error::last_os_error()).context("socket(AF_PACKET)");
            }
            let recv_fd = unsafe { OwnedFd::from_raw_fd(fd) };

            let mut address: libc::sockaddr_ll = unsafe { zeroed() };
            address.sll_family = libc::AF_PACKET as u16;
            address.sll_protocol = ETH_P_ALL.to_be();
            address.sll_ifindex = ifindex;
            let status = unsafe {
                libc::bind(
                    recv_fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_ll).cast(),
                    size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if status < 0 {
                return Err(io::Error::last_os_error()).context("bind(AF_PACKET)");
            }

            let sender = PacketSender::open(interface)?;
            Ok(Self { recv_fd, sender })
        }

        fn into_parts(self) -> (OwnedFd, PacketSender) {
            (self.recv_fd, self.sender)
        }
    }

    struct PacketSender {
        ipv4_fd: OwnedFd,
        ipv6_fd: OwnedFd,
    }

    impl PacketSender {
        fn open(interface: &str) -> Result<Self> {
            let ipv4_fd = open_raw_socket(libc::AF_INET, interface)?;
            let ipv6_fd = open_raw_socket(libc::AF_INET6, interface)?;
            let enabled: libc::c_int = 1;
            let status = unsafe {
                libc::setsockopt(
                    ipv4_fd.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    (&enabled as *const libc::c_int).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if status < 0 {
                return Err(io::Error::last_os_error()).context("setsockopt(IP_HDRINCL)");
            }
            let status = unsafe {
                libc::setsockopt(
                    ipv6_fd.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_HDRINCL,
                    (&enabled as *const libc::c_int).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if status < 0 {
                return Err(io::Error::last_os_error()).context("setsockopt(IPV6_HDRINCL)");
            }
            Ok(Self { ipv4_fd, ipv6_fd })
        }

        fn send(&self, packet: &[u8]) -> io::Result<()> {
            let sent = match packet.first().map(|v| v >> 4) {
                Some(4) if packet.len() >= 20 => {
                    let mut address: libc::sockaddr_in = unsafe { zeroed() };
                    address.sin_family = libc::AF_INET as u16;
                    address.sin_addr.s_addr = u32::from_ne_bytes(packet[16..20].try_into().expect("four-byte IPv4 address"));
                    unsafe {
                        libc::sendto(
                            self.ipv4_fd.as_raw_fd(),
                            packet.as_ptr().cast(),
                            packet.len(),
                            0,
                            (&address as *const libc::sockaddr_in).cast(),
                            size_of::<libc::sockaddr_in>() as libc::socklen_t,
                        )
                    }
                }
                Some(6) if packet.len() >= 40 => {
                    let mut address: libc::sockaddr_in6 = unsafe { zeroed() };
                    address.sin6_family = libc::AF_INET6 as u16;
                    address.sin6_addr.s6_addr.copy_from_slice(&packet[24..40]);
                    unsafe {
                        libc::sendto(
                            self.ipv6_fd.as_raw_fd(),
                            packet.as_ptr().cast(),
                            packet.len(),
                            0,
                            (&address as *const libc::sockaddr_in6).cast(),
                            size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                        )
                    }
                }
                _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "not an IPv4/IPv6 packet")),
            };
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
            if sent as usize != packet.len() {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short AF_PACKET send"));
            }
            Ok(())
        }
    }

    fn open_raw_socket(family: libc::c_int, interface: &str) -> Result<OwnedFd> {
        let fd = unsafe { libc::socket(family, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_RAW) };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("socket(IPPROTO_RAW)");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let interface = CString::new(interface).context("interface contains a NUL byte")?;
        let status = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                interface.as_ptr().cast(),
                interface.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if status < 0 {
            return Err(io::Error::last_os_error()).context("setsockopt(SO_BINDTODEVICE)");
        }
        Ok(fd)
    }

    pub async fn main() -> Result<()> {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("tcp_ip=debug")).try_init();
        match Args::parse().command {
            Command::Daemon {
                interface,
                socket,
                ack_delay_ms,
            } => run_daemon(&interface, &socket, ack_delay_ms).await,
            Command::Listen { socket, address } => client(&socket, &format!("LISTEN {address}")).await,
            Command::Connect { socket, local, peer } => client(&socket, &format!("CONNECT {local} {peer}")).await,
            Command::WriteHex { socket, hex } => {
                decode_hex(&hex)?;
                client(&socket, &format!("WRITE_HEX {hex}")).await
            }
            Command::WriteZero { socket, length } => client(&socket, &format!("WRITE_ZERO {length}")).await,
            Command::ShutdownWrite { socket } => client(&socket, "SHUTDOWN_WRITE").await,
            Command::ExpectReadHex { socket, hex, timeout_ms } => {
                decode_hex(&hex)?;
                client(&socket, &format!("EXPECT_READ_HEX {timeout_ms} {hex}")).await
            }
            Command::ExpectReadZero {
                socket,
                length,
                timeout_ms,
            } => client(&socket, &format!("EXPECT_READ_ZERO {timeout_ms} {length}")).await,
            Command::ExpectEof { socket, timeout_ms } => client(&socket, &format!("EXPECT_EOF {timeout_ms}")).await,
            Command::Status { socket } => client(&socket, "STATUS").await,
            Command::Stop { socket } => client(&socket, "STOP").await,
        }
    }

    async fn client(socket: &Path, command: &str) -> Result<()> {
        let mut stream = UnixStream::connect(socket)
            .await
            .with_context(|| format!("connect control socket {}", socket.display()))?;
        stream.write_all(command.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.shutdown().await?;

        let mut response = String::new();
        BufReader::new(stream).read_line(&mut response).await?;
        let response = response.trim_end();
        println!("{response}");
        if let Some(message) = response.strip_prefix("ERR ") {
            bail!("{message}");
        }
        if !response.starts_with("OK") {
            bail!("invalid daemon response: {response}");
        }
        Ok(())
    }

    async fn run_daemon(interface: &str, socket: &Path, ack_delay_ms: Option<u64>) -> Result<()> {
        if socket.exists() {
            std::fs::remove_file(socket).with_context(|| format!("remove stale socket {}", socket.display()))?;
        }

        let device = PacketDevice::open(interface)?;
        eprintln!("packetdrill_harness: attached to {interface}");
        let (recv_fd, sender) = device.into_parts();
        let tcp_config = TcpConfig {
            retransmission_timeout: Duration::from_millis(200),
            time_wait_timeout: Duration::from_millis(500),
            ack_delay: ack_delay_ms.map(Duration::from_millis),
            ..TcpConfig::default()
        };
        let config = IpStackConfig::builder().tcp_config(tcp_config).build();
        let (stack, ip_send, ip_recv) = create_stack(config)?;
        let state = Arc::new(Mutex::new(AppState::default()));
        let stop = Arc::new(Notify::new());

        let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(256);
        std::thread::Builder::new()
            .name("packetdrill-ingress".into())
            .spawn(move || receive_packets(recv_fd, packet_tx))
            .context("spawn AF_PACKET receive thread")?;
        tokio::spawn(async move {
            while let Some(packet) = packet_rx.recv().await {
                if let Err(error) = ip_send.send_ip_packet(&packet).await {
                    eprintln!("packetdrill_harness: ingress error: {error}");
                }
            }
        });
        tokio::spawn(send_packets(ip_recv, sender));

        let listener = UnixListener::bind(socket).with_context(|| format!("bind control socket {}", socket.display()))?;
        let result = control_loop(listener, stack, state, stop.clone()).await;
        stop.notify_waiters();
        let _ = std::fs::remove_file(socket);
        result
    }

    fn receive_packets(fd: OwnedFd, sender: mpsc::Sender<Vec<u8>>) {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let mut address: libc::sockaddr_ll = unsafe { zeroed() };
            let mut address_len = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            let length = unsafe {
                libc::recvfrom(
                    fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                    (&mut address as *mut libc::sockaddr_ll).cast(),
                    &mut address_len,
                )
            };
            if length < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                eprintln!("packetdrill_harness: AF_PACKET receive failed: {error}");
                return;
            }
            if address.sll_pkttype == PACKET_OUTGOING {
                continue;
            }
            let packet = &buffer[..length as usize];
            if !is_tcp_ip_packet(packet) {
                continue;
            }
            if sender.blocking_send(packet.to_vec()).is_err() {
                return;
            }
        }
    }

    fn is_tcp_ip_packet(packet: &[u8]) -> bool {
        match packet.first().map(|v| v >> 4) {
            Some(4) => packet.get(9).copied() == Some(6),
            Some(6) => packet.get(6).copied() == Some(6),
            _ => false,
        }
    }

    async fn send_packets(mut receiver: IpStackRecv, sender: PacketSender) {
        let mut buffer = vec![0u8; 65_535];
        loop {
            match receiver.recv(&mut buffer).await {
                Ok(length) => {
                    if let Err(error) = sender.send(&buffer[..length]) {
                        eprintln!("packetdrill_harness: raw socket send failed: {error}");
                        return;
                    }
                }
                Err(error) => {
                    eprintln!("packetdrill_harness: stack egress failed: {error}");
                    return;
                }
            }
        }
    }

    async fn control_loop(listener: UnixListener, stack: StackHandle, state: Arc<Mutex<AppState>>, stop: Arc<Notify>) -> Result<()> {
        loop {
            tokio::select! {
                _ = stop.notified() => return Ok(()),
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let should_stop = handle_control(stream, clone_stack(&stack), state.clone()).await?;
                    if should_stop {
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn handle_control(stream: UnixStream, stack: StackHandle, state: Arc<Mutex<AppState>>) -> Result<bool> {
        let (read_half, mut write_half) = stream.into_split();
        let mut line = String::new();
        BufReader::new(read_half).read_line(&mut line).await?;
        let result = execute_command(line.trim(), stack, state).await;
        let should_stop = matches!(result, Ok(CommandResult::Stop));
        let response = match result {
            Ok(CommandResult::Message(message)) => format!("OK {message}\n"),
            Ok(CommandResult::Stop) => "OK stopping\n".to_string(),
            Err(error) => format!("ERR {error:#}\n").replace('\n', " "),
        };
        write_half.write_all(response.as_bytes()).await?;
        write_half.shutdown().await?;
        Ok(should_stop)
    }

    enum CommandResult {
        Message(String),
        Stop,
    }

    async fn execute_command(command: &str, stack: StackHandle, state: Arc<Mutex<AppState>>) -> Result<CommandResult> {
        let mut parts = command.split_whitespace();
        match parts.next() {
            Some("LISTEN") => {
                let address = parse_addr(parts.next(), "listen address")?;
                ensure_no_extra(parts)?;
                mark_pending(&state).await?;
                let mut listener = match bind_listener(stack, address).await {
                    Ok(listener) => listener,
                    Err(error) => {
                        finish_pending(state, Err(error)).await;
                        bail!("failed to bind listener");
                    }
                };
                tokio::spawn(async move {
                    let result = listener.accept().await.map(|(stream, _)| stream);
                    finish_pending(state, result).await;
                });
                Ok(CommandResult::Message("listening".into()))
            }
            Some("CONNECT") => {
                let local = parse_addr(parts.next(), "local address")?;
                let peer = parse_addr(parts.next(), "peer address")?;
                ensure_no_extra(parts)?;
                mark_pending(&state).await?;
                tokio::spawn(async move {
                    let result = connect_stream(stack, local, peer).await;
                    finish_pending(state, result).await;
                });
                Ok(CommandResult::Message("connecting".into()))
            }
            Some("WRITE_HEX") => {
                let bytes = decode_hex(parts.next().ok_or_else(|| anyhow!("missing hex payload"))?)?;
                ensure_no_extra(parts)?;
                let mut guard = wait_for_stream(&state).await?;
                let stream = current_stream(&mut guard)?;
                stream.write_all(&bytes).await?;
                Ok(CommandResult::Message(format!("wrote {} bytes", bytes.len())))
            }
            Some("WRITE_ZERO") => {
                let length: usize = parts
                    .next()
                    .ok_or_else(|| anyhow!("missing length"))?
                    .parse()
                    .context("invalid length")?;
                ensure_no_extra(parts)?;
                let mut guard = wait_for_stream(&state).await?;
                current_stream(&mut guard)?.write_all(&vec![0; length]).await?;
                Ok(CommandResult::Message(format!("wrote {length} zero bytes")))
            }
            Some("SHUTDOWN_WRITE") => {
                ensure_no_extra(parts)?;
                let mut guard = wait_for_stream(&state).await?;
                current_stream(&mut guard)?.shutdown().await?;
                Ok(CommandResult::Message("write side shut down".into()))
            }
            Some("EXPECT_READ_HEX") => {
                let timeout = parse_timeout(parts.next())?;
                let expected = decode_hex(parts.next().ok_or_else(|| anyhow!("missing expected hex payload"))?)?;
                ensure_no_extra(parts)?;
                let mut guard = wait_for_stream(&state).await?;
                let stream = current_stream(&mut guard)?;
                let mut actual = vec![0; expected.len()];
                tokio::time::timeout(timeout, stream.read_exact(&mut actual))
                    .await
                    .context("timed out waiting for stream data")??;
                if actual != expected {
                    bail!("read mismatch: expected {}, got {}", encode_hex(&expected), encode_hex(&actual));
                }
                Ok(CommandResult::Message(format!("read {} bytes", actual.len())))
            }
            Some("EXPECT_READ_ZERO") => {
                let timeout = parse_timeout(parts.next())?;
                let length: usize = parts
                    .next()
                    .ok_or_else(|| anyhow!("missing length"))?
                    .parse()
                    .context("invalid length")?;
                ensure_no_extra(parts)?;
                let mut guard = wait_for_stream(&state).await?;
                let stream = current_stream(&mut guard)?;
                let mut actual = vec![0; length];
                tokio::time::timeout(timeout, stream.read_exact(&mut actual))
                    .await
                    .context("timed out waiting for stream data")??;
                if let Some((index, byte)) = actual.iter().enumerate().find(|(_, byte)| **byte != 0) {
                    bail!("expected zero payload, byte {index} was {byte:#04x}");
                }
                Ok(CommandResult::Message(format!("read {length} zero bytes")))
            }
            Some("EXPECT_EOF") => {
                let timeout = parse_timeout(parts.next())?;
                ensure_no_extra(parts)?;
                let mut guard = wait_for_stream(&state).await?;
                let stream = current_stream(&mut guard)?;
                let mut byte = [0u8; 1];
                let length = tokio::time::timeout(timeout, stream.read(&mut byte))
                    .await
                    .context("timed out waiting for EOF")??;
                if length != 0 {
                    bail!("expected EOF, read byte {:02x}", byte[0]);
                }
                Ok(CommandResult::Message("EOF observed".into()))
            }
            Some("STATUS") => {
                ensure_no_extra(parts)?;
                let guard = state.lock().await;
                let status = if let Some(error) = &guard.last_error {
                    format!("failed {error}")
                } else if guard.stream.is_some() {
                    "connected".into()
                } else if guard.pending {
                    "pending".into()
                } else {
                    "idle".into()
                };
                Ok(CommandResult::Message(status))
            }
            Some("STOP") => {
                ensure_no_extra(parts)?;
                Ok(CommandResult::Stop)
            }
            Some(other) => bail!("unknown command {other}"),
            None => bail!("empty command"),
        }
    }

    async fn mark_pending(state: &Arc<Mutex<AppState>>) -> Result<()> {
        let mut guard = state.lock().await;
        if guard.pending || guard.stream.is_some() {
            bail!("a stream is already pending or connected");
        }
        guard.pending = true;
        guard.last_error = None;
        Ok(())
    }

    async fn finish_pending(state: Arc<Mutex<AppState>>, result: io::Result<TcpStream>) {
        let mut guard = state.lock().await;
        guard.pending = false;
        match result {
            Ok(stream) => guard.stream = Some(stream),
            Err(error) => guard.last_error = Some(error.to_string()),
        }
    }

    async fn wait_for_stream(state: &Arc<Mutex<AppState>>) -> Result<OwnedMutexGuard<AppState>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let guard = state.clone().lock_owned().await;
            if guard.stream.is_some() || guard.last_error.is_some() || !guard.pending {
                return Ok(guard);
            }
            drop(guard);
            if tokio::time::Instant::now() >= deadline {
                bail!("timed out waiting for pending stream");
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    fn current_stream(state: &mut AppState) -> Result<&mut TcpStream> {
        if let Some(error) = &state.last_error {
            bail!("stream setup failed: {error}");
        }
        state.stream.as_mut().ok_or_else(|| {
            if state.pending {
                anyhow!("stream is still pending")
            } else {
                anyhow!("no current stream")
            }
        })
    }

    fn parse_addr(value: Option<&str>, name: &str) -> Result<SocketAddr> {
        value
            .ok_or_else(|| anyhow!("missing {name}"))?
            .parse()
            .with_context(|| format!("invalid {name}"))
    }

    fn parse_timeout(value: Option<&str>) -> Result<Duration> {
        let millis: u64 = value
            .ok_or_else(|| anyhow!("missing timeout"))?
            .parse()
            .context("invalid timeout")?;
        Ok(Duration::from_millis(millis))
    }

    fn ensure_no_extra<'a>(mut parts: impl Iterator<Item = &'a str>) -> Result<()> {
        if let Some(extra) = parts.next() {
            bail!("unexpected argument {extra}");
        }
        Ok(())
    }

    fn decode_hex(value: &str) -> Result<Vec<u8>> {
        if !value.len().is_multiple_of(2) {
            bail!("hex payload must have an even number of digits");
        }
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).expect("hex input is valid UTF-8");
                u8::from_str_radix(pair, 16).with_context(|| format!("invalid hex byte {pair}"))
            })
            .collect()
    }

    fn encode_hex(value: &[u8]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[cfg(not(feature = "global-ip-stack"))]
    fn create_stack(config: IpStackConfig) -> io::Result<(StackHandle, IpStackSend, IpStackRecv)> {
        ip_stack(config)
    }

    #[cfg(feature = "global-ip-stack")]
    fn create_stack(config: IpStackConfig) -> io::Result<(StackHandle, IpStackSend, IpStackRecv)> {
        let (send, recv) = ip_stack(config)?;
        Ok((StackHandle, send, recv))
    }

    #[cfg(not(feature = "global-ip-stack"))]
    async fn bind_listener(stack: StackHandle, address: SocketAddr) -> io::Result<TcpListener> {
        TcpListener::bind(stack, address).await
    }

    #[cfg(feature = "global-ip-stack")]
    async fn bind_listener(_stack: StackHandle, address: SocketAddr) -> io::Result<TcpListener> {
        TcpListener::bind(address).await
    }

    #[cfg(not(feature = "global-ip-stack"))]
    async fn connect_stream(stack: StackHandle, local: SocketAddr, peer: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::bind(stack, local)?.connect_to(peer).await
    }

    #[cfg(feature = "global-ip-stack")]
    async fn connect_stream(_stack: StackHandle, local: SocketAddr, peer: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::bind(local)?.connect_to(peer).await
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    linux::main().await
}
