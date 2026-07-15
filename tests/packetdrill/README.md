# packetdrill TCP tests

These scripts test `tcp_ip`, not the host kernel TCP implementation. The harness
captures packetdrill input from `tun0` with `AF_PACKET`, injects complete IP packets
into `IpStackSend`, and sends `IpStackRecv` output back through raw IPv4/IPv6
sockets for packetdrill to verify.

During each case, exact TCP drop rules on `tun0` prevent the host TCP stack from
generating RST packets. Cleanup removes both IPv4/IPv6 rules, the per-case Unix
socket, and the harness process even after a failed script.

The test configuration uses a 200 ms initial retransmission timeout and 500 ms
TIME_WAIT. The delayed-ACK cases explicitly configure 50 ms; other cases use
immediate ACKs. Runner timing tolerance defaults to 150 ms and can be overridden
with `PACKETDRILL_TOLERANCE_USECS`.

Run all cases:

```bash
sudo -E bash scripts/run_packetdrill.sh
```

Run selected cases:

```bash
sudo -E bash scripts/run_packetdrill.sh \
  tests/packetdrill/ipv4/passive_smoke.pkt \
  tests/packetdrill/ipv6/passive_smoke.pkt
```

Set `PACKETDRILL_BIN` to use an existing binary. Otherwise the runner invokes
`scripts/setup_packetdrill.sh`, which builds the pinned upstream revision in
`${PACKETDRILL_CACHE_DIR:-$HOME/.cache/tcp_ip/packetdrill}`.
