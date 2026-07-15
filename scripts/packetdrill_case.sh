#!/usr/bin/env bash
set -euo pipefail

: "${TCP_IP_PD_HARNESS:?TCP_IP_PD_HARNESS is required}"
: "${TCP_IP_PD_SOCKET:?TCP_IP_PD_SOCKET is required}"
: "${TCP_IP_PD_PID_FILE:?TCP_IP_PD_PID_FILE is required}"
: "${TCP_IP_PD_HARNESS_LOG:?TCP_IP_PD_HARNESS_LOG is required}"

delete_rule() {
  local family="$1"
  local tool="iptables"
  [[ "${family}" == "ipv6" ]] && tool="ip6tables"
  while "${tool}" -w -t raw -C PREROUTING -i tun0 -p tcp -j DROP 2>/dev/null; do
    "${tool}" -w -t raw -D PREROUTING -i tun0 -p tcp -j DROP
  done
  while "${tool}" -w -C OUTPUT -m mark --mark 20548 -j DROP 2>/dev/null; do
    "${tool}" -w -D OUTPUT -m mark --mark 20548 -j DROP
  done
}

cleanup() {
  if [[ -S "${TCP_IP_PD_SOCKET}" ]]; then
    "${TCP_IP_PD_HARNESS}" stop --socket "${TCP_IP_PD_SOCKET}" >/dev/null 2>&1 || true
  fi
  if [[ -f "${TCP_IP_PD_PID_FILE}" ]]; then
    pid="$(<"${TCP_IP_PD_PID_FILE}")"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      for _ in {1..20}; do
        kill -0 "${pid}" 2>/dev/null || break
        sleep 0.05
      done
      kill -KILL "${pid}" 2>/dev/null || true
    fi
  fi
  delete_rule ipv4
  delete_rule ipv6
  rm -f -- "${TCP_IP_PD_SOCKET}" "${TCP_IP_PD_PID_FILE}"
}

setup_case() {
  local family="$1"
  local ack_delay_ms="${2:-}"
  cleanup

  local tool="iptables"
  [[ "${family}" == "ipv6" ]] && tool="ip6tables"
  "${tool}" -w -t raw -I PREROUTING 1 -i tun0 -p tcp -j DROP
  # Active-open scripts use a marked kernel socket only to give packetdrill
  # syscall state. Suppress that socket's packets; the userspace stack is the
  # sole system under test and sends unmarked traffic.
  "${tool}" -w -I OUTPUT 1 -m mark --mark 20548 -j DROP

  args=(daemon --interface tun0 --socket "${TCP_IP_PD_SOCKET}")
  if [[ -n "${ack_delay_ms}" ]]; then
    args+=(--ack-delay-ms "${ack_delay_ms}")
  fi
  nohup "${TCP_IP_PD_HARNESS}" "${args[@]}" >"${TCP_IP_PD_HARNESS_LOG}" 2>&1 &
  echo "$!" >"${TCP_IP_PD_PID_FILE}"

  for _ in {1..100}; do
    if [[ -S "${TCP_IP_PD_SOCKET}" ]] && "${TCP_IP_PD_HARNESS}" status --socket "${TCP_IP_PD_SOCKET}" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$(<"${TCP_IP_PD_PID_FILE}")" 2>/dev/null; then
      cat "${TCP_IP_PD_HARNESS_LOG}" >&2 || true
      echo "packetdrill harness exited during startup" >&2
      return 1
    fi
    sleep 0.02
  done
  echo "timed out waiting for packetdrill harness" >&2
  return 1
}

control() {
  local command="${1:?control command is required}"
  shift
  "${TCP_IP_PD_HARNESS}" "${command}" --socket "${TCP_IP_PD_SOCKET}" "$@"
}

case "${1:-}" in
  setup)
    shift
    setup_case "$@"
    ;;
  cleanup)
    cleanup
    ;;
  ctl)
    shift
    control "$@"
    ;;
  *)
    echo "usage: $0 {setup FAMILY [ACK_DELAY_MS]|cleanup|ctl COMMAND ...}" >&2
    exit 2
    ;;
esac
