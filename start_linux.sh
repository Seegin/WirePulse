#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if [ ! -f core/libwirepulse_pcap.so ] && [ ! -f core/libwirepulse_pcap.dylib ]; then
    echo "[WirePulse] Building C11 native libpcap capture engine..."
    bash core/build.sh
fi

python3 wirepulse.py "$@"
