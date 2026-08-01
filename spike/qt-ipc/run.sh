#!/usr/bin/env bash
# Builds and runs the split-process demo: Rust daemon + C++/Qt frontend.
#
#   ./run.sh              launch the demo
#   ./run.sh --headless   render offscreen, save a screenshot, exit
#
# The two halves build completely independently — that is the point.
set -euo pipefail
cd "$(dirname "$0")"

SOCK_DIR=${XDG_RUNTIME_DIR:-/tmp}/veil-spike
mkdir -p "$SOCK_DIR"
export VEIL_SPIKE_SOCKET="$SOCK_DIR/veil.sock"

echo "==> building daemon (cargo, knows nothing about Qt)"
cargo build --manifest-path daemon/Cargo.toml --quiet

echo "==> building gui (cmake, knows nothing about Rust)"
cmake -S gui -B gui/build -G Ninja >/dev/null
cmake --build gui/build >/dev/null

cleanup() { [[ -n ${DAEMON_PID:-} ]] && kill "$DAEMON_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo "==> starting daemon"
./daemon/target/debug/veil-daemon-spike &
DAEMON_PID=$!

# Wait for the socket rather than sleeping blindly.
for _ in $(seq 50); do [[ -S $VEIL_SPIKE_SOCKET ]] && break; sleep 0.1; done

if [[ ${1:-} == --headless ]]; then
	echo "==> running gui offscreen"
	VEIL_AUTOQUIT=1 QT_QPA_PLATFORM=offscreen ./gui/build/veil_gui
	echo "==> screenshot: $PWD/shot.png"
else
	echo "==> launching gui — drag the panels around, they persist across restarts"
	./gui/build/veil_gui
fi
