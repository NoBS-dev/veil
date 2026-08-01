# qt-ipc spike

A working reference for the client architecture in `DESIGN.md` §17: **Rust
backend, C++/Qt frontend, no FFI.**

```sh
./run.sh              # build both halves and launch
./run.sh --headless   # render offscreen, write shot.png, exit
```

Drag the Channels and Members panels anywhere — float them, tab them, move them
to the other side — and restart. The layout persists.

Type in the composer: the text goes to the daemon and comes back as a message,
so what you see rendered has genuinely made the round trip.

## What it demonstrates

| | |
| --- | --- |
| No FFI | `gui/CMakeLists.txt` contains no cargo, no bridge headers, no Rust library |
| Independent builds | each half builds alone; a C++ developer never installs Rust |
| Real crypto in the daemon | a genuine `vodozemac` account — the identity in the status bar is derived in Rust, not a literal the C++ side could have invented |
| Request/response | `hello` → channels, members, identity; `select_channel` → notice |
| Daemon-initiated push | peers "talk" on a timer with nothing polling for them |
| QML → C++ → socket → Rust | the composer round-trips through the daemon before rendering |
| Widgets shell + QML island | `QDockWidget` channel/member panels around a `QQuickWidget` message view |
| Layout persistence | `saveState()` / `restoreState()` via `QSettings` |
| Crash isolation | `SIGKILL` the GUI and the daemon keeps serving |

The GUI binary is ~124 KB. The equivalent statically-linked build was ~3.9 MB,
because it contained the core.

## Layout

```
daemon/   Rust — stands in for veil-client-core + veil-daemon
gui/      C++/Qt — Widgets shell, QML island, QLocalSocket
run.sh    builds both, starts the daemon, launches the GUI
```

The daemon carries its own `[workspace]` so it stays out of the main cargo
workspace; `cargo build --workspace` at the repo root ignores it.

## What this is not

A spike, not a foundation. Deliberately missing, and all noted in §17:

- **Framing is newline-delimited JSON** because it is debuggable with `socat`.
  Length-prefixed framing is wanted before real traffic, since messages will
  carry binary.
- No authentication on the socket, no reconnect logic, no backpressure.
- No real storage, sessions, history, or search. Peers are a scripted
  conversation on a timer; channel switching prints a notice instead of loading
  anything.
- Messages are **echoed by the daemon** rather than rendered optimistically, so
  the round trip is visible. A real client would render immediately and
  reconcile.
- Mouse-driven panel dragging was verified by hand; the automated checks moved
  panels programmatically.

## Why not the linked (`cxx`) alternative

That was also built and also worked — clean build, both directions, threading,
about 30 lines of bridge. It is a viable fallback and is what mobile will need,
since iOS and Android cannot run a background daemon (§17.4).

The split was chosen for desktop because it removes the build coupling entirely
and puts key material in its own address space, away from the process that
parses untrusted images and embeds.
