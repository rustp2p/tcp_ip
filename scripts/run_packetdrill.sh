#!/usr/bin/env bash
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
packetdrill_bin="${PACKETDRILL_BIN:-}"
if [[ -z "${packetdrill_bin}" ]]; then
  packetdrill_bin="$(bash "${repo_root}/scripts/setup_packetdrill.sh")" || exit $?
fi
if [[ ! -x "${packetdrill_bin}" ]]; then
  echo "packetdrill binary is not executable: ${packetdrill_bin}" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "packetdrill tests require root (CAP_NET_ADMIN and CAP_NET_RAW)" >&2
  exit 2
fi

export PATH="${HOME}/.cargo/bin:${PATH}"
cd "${repo_root}" || exit 2
if [[ "${TCP_IP_PD_SKIP_BUILD:-0}" != "1" ]]; then
  cargo build --example packetdrill_harness || exit $?
fi

export TCP_IP_PD_HARNESS="${repo_root}/target/debug/examples/packetdrill_harness"
if [[ ! -x "${TCP_IP_PD_HARNESS}" ]]; then
  echo "packetdrill harness is missing: ${TCP_IP_PD_HARNESS}" >&2
  exit 2
fi
export TCP_IP_PD_CASE="bash ${repo_root}/scripts/packetdrill_case.sh"
run_root="${repo_root}/target/packetdrill"
log_root="${run_root}/logs"
mkdir -p "${log_root}"

cleanup_current_case() {
  if [[ -n "${TCP_IP_PD_SOCKET:-}" && -n "${TCP_IP_PD_PID_FILE:-}" && -n "${TCP_IP_PD_HARNESS_LOG:-}" ]]; then
    bash "${repo_root}/scripts/packetdrill_case.sh" cleanup >/dev/null 2>&1 || true
  fi
}
trap cleanup_current_case EXIT
trap 'exit 130' INT TERM

mapfile -t tests < <(
  if [[ "$#" -gt 0 ]]; then
    printf '%s\n' "$@"
  else
    find "${repo_root}/tests/packetdrill" -type f -name '*.pkt' -print | sort
  fi
)

if [[ "${#tests[@]}" -eq 0 ]]; then
  echo "no packetdrill tests found" >&2
  exit 2
fi

failures=0
extra_args=()
if [[ -n "${PACKETDRILL_EXTRA_ARGS:-}" ]]; then
  read -r -a extra_args <<<"${PACKETDRILL_EXTRA_ARGS}"
fi
for test_path in "${tests[@]}"; do
  if [[ "${test_path}" != /* ]]; then
    test_path="${repo_root}/${test_path}"
  fi
  name="${test_path#"${repo_root}/tests/packetdrill/"}"
  safe_name="${name//\//_}"
  safe_name="${safe_name%.pkt}"
  export TCP_IP_PD_SOCKET="/tmp/tcp_ip-packetdrill-$$-${safe_name}.sock"
  export TCP_IP_PD_PID_FILE="/tmp/tcp_ip-packetdrill-$$-${safe_name}.pid"
  export TCP_IP_PD_HARNESS_LOG="${log_root}/${safe_name}.harness.log"
  packetdrill_log="${log_root}/${safe_name}.packetdrill.log"

  echo "[packetdrill] ${name}"
  "${packetdrill_bin}" --tolerance_usecs="${PACKETDRILL_TOLERANCE_USECS:-150000}" --verbose "${extra_args[@]}" "${test_path}" >"${packetdrill_log}" 2>&1
  status=$?
  cleanup_current_case
  if [[ "${status}" -ne 0 ]]; then
    failures=$((failures + 1))
    echo "FAILED: ${name}" >&2
    cat "${packetdrill_log}" >&2
    if [[ -s "${TCP_IP_PD_HARNESS_LOG}" ]]; then
      echo "--- harness ---" >&2
      cat "${TCP_IP_PD_HARNESS_LOG}" >&2
    fi
  fi
done

if [[ "${failures}" -ne 0 ]]; then
  echo "${failures} packetdrill test(s) failed; logs: ${log_root}" >&2
  exit 1
fi
echo "all ${#tests[@]} packetdrill tests passed"
