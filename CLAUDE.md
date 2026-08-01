# CLAUDE.md

Working notes for Claude Code sessions in this repo.

## What this is

Veil — an end-to-end encrypted messaging platform built on Olm/Megolm
(`vodozemac`), intended to grow into a Discord-like communication platform.

**Read `DESIGN.md` before any architectural work.** It defines the network model,
identity, cross-signing, encryption tiers, and the sequencing of work. Most of it
is *designed but not built* — `DESIGN.md` §2 has the authoritative table of what
actually exists. Do not assume a section describes the codebase.

The shape, so you have it before reading: **no federation.** A community lives on
exactly one host and never replicates. Users reach any host through their own home
server acting as a **blind relay** — nested TLS, so the relay forwards bytes it
cannot read and the host never learns the user's IP. The *only* server-to-server
traffic is DM store-and-forward into the recipient's mailbox (§3.3); no community
state ever crosses a server boundary, which is what keeps Matrix's state
resolution out of the design. Identity is self-certifying and carries no hostname,
so users are portable between home servers. DMs, group chats and calls are E2EE
("Sealed"); communities default to server-readable ("Open") because search,
moderation and bots require it.

## Layout

```
veil-protocol/   shared wire types, signed envelope, replay guard, rate limiter
veil-server/     axum WebSocket relay + HTTP prekey/roster endpoints
veil-client/     CLI client (cli, listener, messaging, state)
```

Planned (§17): `veil-client-core` (Rust library — sessions, keys, storage,
search, network, **no UI dependency**), `veil-daemon` wrapping it behind a local
socket, and `veil-gui` in **C++/Qt** talking to that socket. **No FFI between
them** — Tauri/Electron are ruled out too. Mobile links the core directly and
uses native UI, deferred. Today's `veil-client` interleaves protocol work with
`println!`; separating that is a precondition for the GUI.

`spike/qt-ipc/` is a working reference for that architecture — `./run.sh`. It has
its own `[workspace]`, so `cargo build --workspace` at the root ignores it. It
needs `qt6-base` and `qt6-declarative`.

`veil-protocol` is the crate to treat most carefully — it defines the wire
format and the security primitives. Changes there affect both other crates and
any stored state.

## Commands

```sh
cargo build --workspace
cargo test --workspace                  # unit tests live in veil-protocol
cargo clippy --workspace --all-targets
cargo fmt --all
```

Two pre-existing clippy warnings are known and intentionally left alone
(`CLIENTS` type complexity in the server, a redundant `&` in a `format!` in the
client). Everything else should stay clean.

## Environment

This is an Arch container. The user has passwordless `paru`; install what you
need (`paru -S --noconfirm --needed <pkg>`). The Rust toolchain and
`python-websockets` were installed this way.

Bash tool calls generally need `dangerouslyDisableSandbox: true` — the sandbox
presents a restricted PATH where `cargo`, `paru`, and `pacman` are not visible.

The client stores state in the OS keyring via the Secret Service, which does
work in this container. Test profiles create real keyring entries — clean them
up afterwards:

```sh
secret-tool clear service veil-client username <profile>
```

## Running it

Both binaries prompt interactively on stdin.

```sh
# server: address, then TLS cert path (blank = plaintext)
printf '127.0.0.1:9876\n\n' | ./target/debug/veil-server

# client: profile name, then server address on first run
printf 'alice\n127.0.0.1:9876\n' | ./target/debug/veil-client
```

For a two-client end-to-end test, hold the clients' stdin open with fifos so
they stay connected:

```sh
mkfifo a.in b.in
sleep 40 > a.in & sleep 40 > b.in &
./target/debug/veil-client < a.in > a.log 2>&1 &
./target/debug/veil-client < b.in > b.log 2>&1 &
printf 'alice\n127.0.0.1:9876\n' > a.in
printf 'bob\n127.0.0.1:9876\n'   > b.in
# then, with bob's key from b.log:
printf 'msg\n<bob-key>\nhello\n' > a.in
```

Client CLI commands: `curve`, `ed`, `list`, `msg`, `safety`, `remove`, `quit`.

## Conventions

- **Hard tabs** (`rustfmt.toml` sets `hard_tabs = true`). Run `cargo fmt --all`.
- Comments explain *why*, not *what*. Security-relevant code says what attack a
  check prevents — match that density when touching crypto paths.
- `anyhow` for error handling throughout.
- Rust edition 2024; let-chains (`if let ... && let ...`) are in use.

## Security invariants

These were established deliberately. Do not regress them without saying so
explicitly — each one closes a specific attack.

1. **Identity is proven, never asserted.** The server keys its routing map off
   the verified signer of a challenge/response handshake. A peer claiming an
   identity without a valid signature over a fresh server challenge is dropped.
2. **Signatures verify over received bytes.** `Envelope` carries its payload as
   an opaque `Vec<u8>` so verification runs on exactly what arrived. Never
   re-serialise a decoded struct and verify that instead.
3. **The signing input is domain-separated** and binds pubkey, timestamp, nonce,
   and payload length. Adding a new signed message type must reuse
   `signing_input`, not roll its own.
4. **Every envelope passes a `ReplayGuard`** on both server and client. Key
   uploads additionally must advance a per-identity clock, so a captured upload
   cannot resurrect consumed one-time keys.
5. **Envelopes are pinned to their connection** server-side — a client cannot
   forward envelopes signed by someone else.
6. **Clients pin the server's identity key** on first connect and refuse a
   changed one.
7. **OTK exhaustion degrades, it does not fail.** Past the per-identity budget
   the server serves the fallback key instead of consuming a real OTK.

`veil-protocol` has 9 tests covering envelope forgery, re-attribution, replay,
and the rate limiter. Extend them when touching those paths.

## Working agreements

- The user wants direct technical assessment, including disagreement. Give a
  recommendation rather than a survey of options.
- Verify claims by running things. The e2e recipe above and adversarial scripts
  against a live server are both cheap; prefer them to reasoning about whether
  something works.
- Follow `DESIGN.md` §15 sequencing. Tier 1 (identity, devices, cross-signing,
  message IDs, tier binding, relay transport) comes before Tier 2 (persistence,
  scaling), because Tier 1 is what is expensive to retrofit.
- `DESIGN.md` marks unratified suggestions **[proposal]**. Those are arguable —
  say so rather than treating them as settled.
