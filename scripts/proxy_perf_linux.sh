#!/usr/bin/env bash
set -euo pipefail

duration=15
parallel=1
server_addr="127.0.0.1"
server_port=5201
proxy_addr="10.1.0.2"
warmup=3
reverse=0
json=0
skip_build=0

usage() {
  cat <<'USAGE'
Usage: sudo -E scripts/proxy_perf_linux.sh [options]

Runs an iperf3 throughput test through examples/tcp_proxy.

Options:
  --duration SECONDS     iperf3 test duration (default: 15)
  --parallel N           parallel iperf3 streams (default: 1)
  --server-addr IP       iperf3 server bind address (default: 127.0.0.1)
  --server-port PORT     iperf3 server/proxy test port (default: 5201)
  --proxy-addr IP        destination IP routed into the TUN device (default: 10.1.0.2)
  --warmup SECONDS       warmup duration before the measured run (default: 3, 0 disables)
  --reverse              run iperf3 reverse mode
  --json                 save measured iperf3 output as JSON
  --skip-build           skip cargo build
  -h, --help             show this help

The script creates logs under target/proxy-perf/<timestamp>/.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)
      duration="$2"
      shift 2
      ;;
    --parallel)
      parallel="$2"
      shift 2
      ;;
    --server-addr)
      server_addr="$2"
      shift 2
      ;;
    --server-port)
      server_port="$2"
      shift 2
      ;;
    --proxy-addr)
      proxy_addr="$2"
      shift 2
      ;;
    --warmup)
      warmup="$2"
      shift 2
      ;;
    --reverse)
      reverse=1
      shift
      ;;
    --json)
      json=1
      shift
      ;;
    --skip-build)
      skip_build=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "tcp_proxy creates a TUN device; rerun as root, for example: sudo -E $0 $*" >&2
  exit 1
fi

command -v cargo >/dev/null 2>&1 || {
  echo "cargo not found in PATH" >&2
  exit 1
}
command -v iperf3 >/dev/null 2>&1 || {
  echo "iperf3 not found in PATH" >&2
  exit 1
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

if [[ "${skip_build}" -eq 0 ]]; then
  cargo build --release --example tcp_proxy --features global-ip-stack
fi

proxy_bin="${repo_root}/target/release/examples/tcp_proxy"
if [[ ! -x "${proxy_bin}" ]]; then
  echo "tcp_proxy binary not found: ${proxy_bin}" >&2
  exit 1
fi

timestamp="$(date +%Y%m%d-%H%M%S)"
out_dir="${repo_root}/target/proxy-perf/${timestamp}"
mkdir -p "${out_dir}"

server_log="${out_dir}/iperf3-server.log"
proxy_log="${out_dir}/tcp_proxy.log"
warmup_log="${out_dir}/warmup.txt"
result_file="${out_dir}/result.txt"
if [[ "${json}" -eq 1 ]]; then
  result_file="${out_dir}/result.json"
fi

iperf3 -s -B "${server_addr}" -p "${server_port}" >"${server_log}" 2>&1 &
server_pid=$!

RUST_LOG="${RUST_LOG:-warn}" "${proxy_bin}" --server-addr "${server_addr}:${server_port}" >"${proxy_log}" 2>&1 &
proxy_pid=$!

cleanup() {
  kill "${proxy_pid}" "${server_pid}" >/dev/null 2>&1 || true
  wait "${proxy_pid}" "${server_pid}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 2

iperf_args=(-c "${proxy_addr}" -p "${server_port}" -P "${parallel}")
if [[ "${reverse}" -eq 1 ]]; then
  iperf_args+=(-R)
fi

if [[ "${warmup}" -gt 0 ]]; then
  echo "warmup: iperf3 ${iperf_args[*]} -t ${warmup}"
  iperf3 "${iperf_args[@]}" -t "${warmup}" | tee "${warmup_log}"
fi

echo "measured: iperf3 ${iperf_args[*]} -t ${duration}"
if [[ "${json}" -eq 1 ]]; then
  iperf3 "${iperf_args[@]}" -t "${duration}" -J | tee "${result_file}"
else
  iperf3 "${iperf_args[@]}" -t "${duration}" | tee "${result_file}"
fi

echo "logs: ${out_dir}"
