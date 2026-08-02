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

The server prompts for a database path and keeps its key directory and
mailboxes there (§12.1) — it survives restarts, and mail for an offline device
waits rather than being dropped.

```sh
cargo build --workspace
cargo test --workspace                  # unit tests live in veil-protocol
cargo clippy --workspace --all-targets
cargo fmt --all
```

One pre-existing clippy warning is known and left alone (a redundant `&` in a
`format!` in the client). Everything else should stay clean.

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
# server: address, TLS cert path (blank = plaintext), database path
printf '127.0.0.1:9876\n\n\n' | ./target/debug/veil-server

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

Client CLI commands: `curve`, `ed`, `list`, `msg`, `devices`, `safety`, `remove`, `quit`.

A profile may carry a relay (§3.2). With one set the client tunnels through it,
so the destination sees the relay's address rather than the client's. Test it by
running two servers and giving one as the relay:

```sh
printf '127.0.0.1:9901\n\n' | ./target/debug/veil-server   # destination
printf '127.0.0.1:9902\n\n' | ./target/debug/veil-server   # relay
# then at the client prompts: server 127.0.0.1:9901, relay 127.0.0.1:9902
```

Addresses are `<user-id>/<device-id>` in base32 (§5.3) — `msg` and the prekey
endpoint both take that form, not a raw key. Profiles predating the identity
model are refused on load rather than migrated; use `remove` or a new profile.

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
8. **A device's claim to a user is verified, not asserted.** The handshake walks
   `device key <- SSK <- MSK -> user id` (§5.4), against the key that actually
   signed the envelope. Master keys are public, so quoting one proves nothing on
   its own.
9. **Enrolling a device never touches the master key.** That is why the
   self-signing key exists; a master-key signature over a device is *not*
   accepted as a device signature.
10. **Device lists served by a host are untrusted input.** Every entry is
    checked against the owner's cross-signing keys before it is believed;
    entries that fail are dropped rather than failing the whole list.
11. **Queued mail is dropped only on acknowledgement.** The server has exactly
    one delete path and it runs when a client says a message arrived — sending
    is not receiving, so a client that dies mid-flush gets the mail again.
    Acknowledgement is scoped to the acknowledging device, since an id is just a
    row number.
12. **A message's id is recomputed, never read off the wire.** It is a hash of
    the message, so a claimed id cannot disagree with the content. Duplicates
    are dropped *before* any Olm work, since decrypting twice would advance a
    ratchet for a message already handled.
13. **A community's encryption mode is inside its id.** `CommunityId` hashes the
    root record, mode included, so a host cannot serve a different mode under
    the same id. Anything that might ever change belongs in the signed policy
    chain instead — a root field is frozen for the community's life.
14. **Version ranges are negotiated inside signed envelopes, and echoed back.**
    Signing alone is not enough — an old challenge is genuinely signed, so the
    client replay-guards it and the server checks the client saw the range it
    actually advertised. Both are downgrade defences.
15. **The relay is not an arbitrary tunnel.** It authenticates the user first
    (so limits are per user), and refuses any destination that cannot produce a
    signed Veil challenge. That check is what stops it being an open proxy —
    it cannot be pointed at a web server at all, rather than merely being
    discouraged from it.
16. **Policy needs k *distinct* controllers.** One controller signing twice must
    not reach the threshold, or k-of-n collapses to 1-of-n. Sequences must
    advance, or a stale migration could redirect a community backwards.

`veil-protocol` has 63 tests covering envelope forgery, re-attribution, replay,
the rate limiter, user/device identity (§5.1-5.3), cross-signing (§5.4) and the
message model (§10).
Extend them when touching those paths.

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
