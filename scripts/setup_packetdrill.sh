#!/usr/bin/env bash
set -euo pipefail

readonly PACKETDRILL_COMMIT="2c4001c4d6fc04a3bbd01d4b92be62717a37648a"
cache_root="${PACKETDRILL_CACHE_DIR:-${HOME}/.cache/tcp_ip/packetdrill}"

install_deps=false
[[ "${1:-}" == "--install-deps" ]] && install_deps=true
for command in git gcc make bison flex python3 ifconfig iptables; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    install_deps=true
    break
  fi
done

if [[ "${install_deps}" == "true" ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "packetdrill build dependencies are missing; rerun setup as root" >&2
    exit 2
  fi
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y git gcc make bison flex python3 net-tools iptables
fi

mkdir -p "$(dirname "${cache_root}")"
if [[ ! -d "${cache_root}/.git" ]]; then
  git clone https://github.com/google/packetdrill.git "${cache_root}" >&2
fi

git -C "${cache_root}" fetch origin "${PACKETDRILL_COMMIT}" >&2
git -C "${cache_root}" checkout --detach "${PACKETDRILL_COMMIT}" >&2

source_dir="${cache_root}/gtests/net/packetdrill"
(
  cd "${source_dir}"
  ./configure >&2
  make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >&2
)

printf '%s\n' "${source_dir}/packetdrill"
