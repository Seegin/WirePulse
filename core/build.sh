#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

UNAME_S="$(uname -s)"
if [ "$UNAME_S" = "Darwin" ]; then
    OUT="libwirepulse_pcap.dylib"
    gcc -O3 -std=c11 -Wall -Wextra -dynamiclib -fPIC capture_engine.c -o "$OUT" -ldl
else
    OUT="libwirepulse_pcap.so"
    gcc -O3 -std=c11 -Wall -Wextra -shared -fPIC capture_engine.c -o "$OUT" -ldl
fi

echo "[WirePulse Core] Built native capture library: $SCRIPT_DIR/$OUT"
