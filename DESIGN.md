# Veil — Architecture and Protocol Design

> **Status of this document.** This describes the *target* architecture. Most of
> it is not built yet. Section 2 states precisely what exists today versus what
> is only designed here. Do not read a section as a description of the codebase
> unless it is marked **[built]**.
>
> Sections marked **[proposal]** are design suggestions that have not been
> ratified. They are written concretely so they can be argued with, not because
> the decision is settled. **There are currently none outstanding** — every
> mechanism here is either decided or listed as an open question in §16.

---

## 1. What Veil is

An end-to-end encrypted communication platform, built so that Discord-like
functionality — communities, channels, roles, voice, bots — can be layered on
top without renegotiating the cryptographic foundations.

The bet is that the foundations are the expensive part. Identity, device
management, key agreement, the network model, and the message model are all
things that are cheap to design correctly now and brutally expensive to migrate
later, because every stored session, every peer's pinned trust, and every
message reference has to be rewritten. Feature work is comparatively mechanical.

### 1.1 Shape of the network, in one paragraph

Anyone can run a server. A community lives on exactly **one** host — there is no
replication and no federation. Users reach any host through their **own** home
server, which acts as a **blind relay**: it forwards an encrypted tunnel it
cannot read, so the community host never learns the user's IP. A client only ever
connects to its own home server; for DMs that server also does store-and-forward
delivery to the recipient's server (§3.4), which is the one place servers speak
to each other, and only ever to hand over opaque blobs. Identity is
self-certifying and portable, so a user is not welded to the server their account
lives on.

### 1.2 Design principles

1. **Foundations before features.** Anything that ends up embedded in stored
   state or in peers' trust decisions gets designed before it gets built.
2. **One pipeline, two payload modes.** Identity, routing, ordering, delivery,
   and history are identical across encryption tiers. Only the payload differs.
3. **The server is not trusted for identity.** Identifiers are self-certifying;
   no server can substitute keys or claim a user is someone else.
4. **No silent downgrades.** A security property never weakens underneath a user
   without them knowing.
5. **Relays are infrastructure, not parties.** A home server carries traffic it
   cannot read. It is never in the trust set for content.
6. **Self-hosting stays viable.** Not popular — *viable*. See §1.3; this is the
   invariant the whole architecture exists to protect.
7. **Swappable crypto layers.** Group key agreement sits behind an interface so
   Megolm can be replaced without rewriting everything above it.

### 1.3 Centralisation posture

Three independent forces push toward consolidation on a few large servers:
reputation gatekeeping (§11.4), relay bandwidth cost (§9.1), and discovery
(§11.5). Each alone is sufficient. Matrix has the same shape and the result is
visible in matrix.org's share of users.

**Consolidation is accepted.** Most users will end up on a handful of large home
servers, and that is fine. Chasing an even distribution is not a goal, and
designing against it would cost more than it is worth.

**What is not accepted is the door closing.** The invariant:

> One person on a domestic connection must be able to run a home server for
> themselves and a few dozen friends, reach any community, and host a community
> of their own — without permission from anyone.

This is a testable property, not a sentiment. Any change that makes self-hosting
require an allowlist entry, a directory listing, a commercial verification
account, a static IP, or bandwidth beyond a home connection is a **regression**,
and should be treated as one even if it improves the experience for the majority.

That is the entire point of the architecture: complete privacy remains available
to anyone willing to run their own box, regardless of how many people choose not
to.

---

## 2. Current state versus design

| Area | Status |
| --- | --- |
| Signed envelope, replay defence | **[built]** `veil-protocol/src/lib.rs` |
| Connection authentication (challenge/response) | **[built]** `veil-server/src/main.rs` |
| 1:1 Olm sessions, prekey/fallback bundles | **[built]** |
| Safety numbers, user verification | **[built]** `safety` command, `verify_user` |
| Optional TLS transport | **[built]** |
| Prekey/roster rate limiting | **[built]** |
| Relay tunnel, destination verification, per-user limits | **[built]** `veil-server` `/relay` |
| Nested TLS through the tunnel, certificate binding | **[built]** `veil-client/src/tunnel.rs`, `veil-server/src/tlsframe.rs` |
| DM mailboxes, local | **[built]** `store.rs`, acknowledgement-scoped |
| DM store-and-forward across servers | **[built]** `veil-server/src/delivery.rs` |
| Protocol version negotiation | **[built]** `version.rs` |
| User/device separation, multi-device | **[built]** `identity.rs` |
| Cross-signing, verifiable device lists | **[built]** `crosssign.rs` |
| Community roots, policy chain, mode binding | **[built]** `community.rs`, served over a transport |
| Communities and channels on a host | **[built]** `veil-server/src/community.rs` — create, join, post, backfill, host-assigned ordering |
| Moderation and reporting under Sealed | **[built]** reports held for a moderator; unattributed accepted |
| Megolm group messaging, `GroupKeyProvider` | **[built]** `groupkeys.rs`, wired into the client — Sealed channels encrypt end-to-end |
| Roles: read-vs-rest split, signed role state | **[built]** `Role` in the signed chain; host enforces post/join/backfill |
| Calls: 1:1 signalling and negotiation | **[built]** `media.rs` — real WebRTC, offer/answer over the Olm session |
| Calls: RTP audio over SRTP | **[built]** Opus track, real packets through the buffer |
| Calls: jitter buffering and pacing | **[built]** wired into the receive path |
| Calls: capture, playback, Opus codec | **[built]** cpal + libopus; degrades on a machine with no devices |
| Calls: mesh for small groups | designed, §9 — same primitives |
| Calls: SFU and SFrame for large groups | designed, §9 — the only place new crypto appears |
| Message model, hash chain, `seen_head` | **[built]** `message.rs` |
| Attachments and media | **[built]** `attachment.rs`, blob store; encryption follows the tier |
| Presence, typing, read state | **[built]** ephemeral, per-community, never logged |
| Search (client-side index) | **[built]** encrypted store, FTS index inside it; Tantivy still the answer at scale |
| Deletion, tombstoning | **[built]** author or moderator; chain survives |
| Attestations, standing | **[built]** `attestation.rs` |
| Finding people: aliases, contact links, pinning | **[built]** §11.6 |
| Reputation and server discovery | designed, §11.4–11.5 |
| Key directory and mailboxes | **[built]** `veil-server/src/store.rs` |
| Message store, push | designed, §12.1–12.2 |
| Backups, succession, migration | designed, §12.3–12.4 |
| Key backup, recovery key, enrolment bundles | **[built]** `keybackup.rs` |
| Horizontal scaling | designed, §13.1–13.3 |
| Time synchronisation | **[built]** `clock.rs`, server-side |
| Client architecture (seam, Qt, mobile) | designed, §17 |
| Client split: Rust daemon + C++/Qt over a socket | **validated by spike**, §17.3 |
| Channel roles and moderation | **[built]** |
| Bots | **[built]** §18 — an account, marked as automated |

§4 (threat model), §6 (trust establishment), §14 (metadata) and §15 (sequencing)
are analysis rather than subsystems and carry no build status of their own.

Today's implementation is a working **single-server** deployment for 1:1
encrypted text between CLI clients: identities cross-sign, devices are verified
before a session opens, state survives a restart, and mail for an offline device
waits in a mailbox until that device acknowledges it.

Mail crosses server boundaries (§3.4), so two people on different home servers
can reach each other, and the relay is genuinely blind (§3.2) — it carries an
end-to-end TLS session it cannot read, and validates only that what passes is
TLS at all.

Communities exist on a host: they can be founded, joined and posted to, and the
host assigns every message a position in a hash chain (§10.1) so no member can
claim one. Membership gates both writing and reading history.

Sealed channels work end to end, including removal. A sender derives its readers from the
community's *signed policy chain* — never from the host, since read access is
key possession and a host that supplied the reader set could add itself — then
delivers a Megolm session to each reader device over Olm and encrypts with it.
A channel with no signed `ChannelReaders` record is refused rather than defaulted
to the host's membership list, and a client that cannot encrypt refuses to post
rather than falling back to plaintext.

Removing a reader rotates the key, so the removed device reads nothing sent
afterwards while keeping what it already held — removal is not retroactive, and
pretending otherwise would be a promise the design cannot keep, since they may
have kept a copy. That binds *every* sender, not only the controller who signed
the removal: the host pushes the new chain to all connected members, and a
client refreshes on connect before it will encrypt anything.

**A host withholding the newest policy record is now detectable.** It was not,
and the fix is worth stating because it cost nothing structural. Sequence numbers
already stopped the chain being rewound but not truncated, so a host could hide
the tip and leave a sender encrypting to a device already removed.

Every message now carries its sender's **policy head** — the highest sequence
they had applied, and a rolling hash of everything applied to reach it — inside
the encrypted body, where the host can neither read nor strip it. A recipient
compares it with their own:

| Sender's head | Means |
| --- | --- |
| Ahead of ours | our chain is short: we are behind, or our host is withholding |
| Behind ours | the sender used stale policy, so this may have reached somebody since removed |
| Same sequence, different hash | the host has served two different chains. Not lag |

This does not *prevent* withholding, and nothing served by a single host could.
It converts a silent failure into a visible one, which is the same bargain §10.1
strikes for history — and it is what makes the residual risk something a person
can act on rather than something nobody learns about. Worth
weighing against the alternative, which is replicating policy between servers and
bringing back everything §3.3 exists to avoid.

Roles are built on the split §8.5 argues for. `Role` lives in the signed policy
chain — one source of truth, so a host cannot grant itself moderation — and the
host enforces the permissions it *can* enforce: posting, joining and backfill are
actions it simply refuses. Reading is not among them, because it is the one
permission a host cannot claw back, so it stays key possession and lives entirely
in the client.

A ban is a role rather than a deletion, so it survives the member leaving and
rejoining. It is deliberately **not** the same as revoking read access: a banned
member keeps every Megolm key they already hold, and stopping them reading what
comes next means taking them out of the reader list, which rotates the session.
The client says so rather than letting the two be confused — §8.5's asymmetry
between a cheap permission change and an expensive one, surfaced instead of
hidden.

Deletion is tombstoning (§10.5) and the chain survives it, which is the property
content-addressing was arranged to give for free. An author may delete their own
message; a moderator may delete anyone's.

One thing worth recording, because it was found by testing rather than by
reasoning: blanking the row is **not** enough to make the content gone. SQLite
leaves the original bytes in the write-ahead log, so a test that grepped the
store still found a deleted message. A checkpoint after tombstoning is what
actually removes them, and §10.5's claim that the host's copy is "not
recoverable from the server" was false until that was added.

Attachments follow the container's tier (§10.2). A Sealed community encrypts
client-side with a fresh key per file and carries the key inside the Megolm body,
so the host holds bytes it cannot read; an Open one stores the file, which is
what lets a host thumbnail and transcode. The per-file toggle is deliberately
absent — it would be a silent downgrade one member makes for everyone. Blobs are
content-addressed and the recipient checks the hash, so a host cannot serve
different bytes under the same reference.

Reporting works the way §7.6 describes: a Sealed host cannot read what is
reported, so it holds the reporter's account for a moderator who can. A report
without cryptographic attribution is accepted and treated as signal for human
review — requiring proof would cost the reporter more privacy than the report is
worth, since a Megolm session exported at one message's index decrypts everything
from there forward.

Channels are declared in the signed chain, with a topic each. A community that
has declared none accepts any name — otherwise a new one would be unusable until
somebody remembered to declare `general` — and once a set exists it is enforced.

Presence, typing and read state are ephemeral (§10.3): no sequence, no chain, no
row, and nothing in the store. Scoped to one community, because that is where the
answer already exists — one community, one host, one subscriber list. There is
deliberately no cross-community presence, since "is Alice online somewhere" would
need a global view no component has.

What remains is
**presence and read state** (§10.3), **search** (§10.4) and **discovery**
(§11.4–11.6), all designed but unbuilt; **calls** (§9), which need a media stack
this has not begun; and **bots**, which are not designed. The client split
(§17) is validated by a spike and remains the largest structural piece.

---

## 3. Network architecture

### 3.1 No federation

Matrix-style federation replicates room state and content to every homeserver
with a member present. Veil does not do this. A community is hosted by exactly
one server, which is authoritative for it.

What this buys:

- **No state resolution.** Matrix's hardest and most bug-prone subsystem exists
  only because multiple servers hold divergent copies of room state. With one
  authoritative host the problem does not exist.
- **One operator per community.** Content is not sprayed across a dozen
  third-party servers. This is what makes the Open tier (§7) defensible: the
  only party who can read an Open community is the operator of the community you
  chose to join.
- **Radically less protocol surface.** No community state crosses a server
  boundary, so no eventual consistency and no cross-server auth rules. The only
  server-to-server traffic anywhere is DM store-and-forward (§3.3), which carries
  opaque blobs and no shared state.

What it costs: **no resilience through replication.** If the host is down the
community is unreachable. That is an accepted trade, answered by migration
(§12.4) and multi-machine hosting (§13.2), not by replication.

### 3.2 Home servers are blind relays

A user's account lives on a home server. Its job is identity anchoring, mailbox
storage, push, and — critically — relaying.

Community hosts are run by strangers. Connecting to one directly exposes the
user's IP to whoever runs it. So the client does not connect directly:

```
client ──TLS──► home server ──TCP──► community host
       └──────────── TLS ─────────────────┘
                (nested, end-to-end)
```

The client opens a session to its home server, asks it to open a tunnel to the
target host, and then runs a **second TLS session end-to-end with that host
inside the tunnel**. The home server forwards opaque bytes.

**This is a blind relay, not a proxy.** A terminating proxy would read every
message its users send to Open communities, putting two operators in the trust
set and undoing the main benefit of §3.1. Nested TLS keeps the relay out of the
trust set entirely.

What each party learns:

| Party | Learns | Does not learn |
| --- | --- | --- |
| Home server | that user U is talking to host H, volume, timing | content |
| Community host | UserId, home server attestation, relay IP | user's IP or location |

**What this protects is network location, not identity or participation.** The
community host necessarily knows who is speaking in it. The UI must say this
plainly rather than implying anonymity.

#### Relay abuse: the open-proxy problem

A server that opens TCP connections to arbitrary destinations on a user's behalf
and cannot inspect the traffic **is an open proxy**. Users could route attacks
through their home server's IP, and the operator could neither see it nor prove
innocence — the blindness that protects users also blinds the operator. Hobbyist
operators get their hosting terminated for this.

Blind forwarding and abuse prevention are in genuine tension, so the relay is
**not** an arbitrary tunnel. Three constraints, none of which require reading
content:

1. **Verify the destination speaks Veil, before tunnelling.** The relay itself
   completes the signed server handshake against the destination (§4.3,
   **[built]** as the challenge/response in `veil-server`) and refuses to
   establish the tunnel otherwise. This is the load-bearing one: it means the
   relay cannot be pointed at a web server, a game server, or a DNS resolver at
   all, which removes the general open-proxy vector rather than mitigating it.
2. **Validate outer framing.** Forward only well-formed records to a verified
   destination. Malformed or oversized framing is dropped.
3. **Rate limit per user** — connection rate, destination count, and sustained
   bytes. Bounds relay-to-relay flooding between legitimate Veil hosts, which
   step 1 does not address.

**Framing: validate TLS records, do not define a Veil outer frame.** Decided.

A custom outer frame would let the relay distinguish message types, but it
couples relay upgrades to protocol evolution: a relay on older software could not
forward newer frame types, so every protocol change would need a fleet upgrade
before it could ship. TLS records already expose type and length while keeping
contents encrypted, which satisfies constraints 2 and 3 at no versioning cost.

If richer inspection ever proves necessary, add a **minimal outer frame versioned
independently of the inner protocol** — type and length only, stable across
protocol changes — so relays never need updating in lockstep.

**Nested TLS is built.** The tunnel carries opaque bytes to a TCP connection and
validates TLS record framing; the client runs a second TLS session end-to-end
with the destination inside it.

The certificate is bound to the Veil identity rather than to a certificate
authority. The destination hashes its own certificate and signs that hash into
the challenge (`Challenge::tls_binding`); the client refuses if the certificate
it negotiated does not match. A relay that terminated the inner session would
have to present its own certificate, and cannot make the destination's identity
key vouch for it.

**Requiring a CA would have broken §1.3.** A self-hoster's certificate is
self-signed, so "validate against a CA" and "anyone can host a community" cannot
both hold. Binding to the identity key needs no authority at all, and inherits
the trust-on-first-use property the identity key already has (invariant 6) —
no more and no less. The residual limitation used to be the usual one for TOFU: on a *first*
connection, nothing distinguished the intended host from another genuine Veil
host something in the path had chosen — and because that host is real, every
check afterwards would pass against the wrong server.

**Invites close it, and are now the primary way to reach a host.** An invite is
`veil:<community>:<host-key>:<host>` and carries the identity key the host must
present, checked at the first handshake rather than after connecting — by the
time a client has pinned, there is nothing left to protect. Connecting without
one still works, because §3.5 wants a stranded user to have a way through, but
the client names it as a blind pin rather than letting the two look equivalent.

The trust does not vanish; it moves to whoever shared the link, which is where a
person can reason about it. A forged invite is still a forged invite. What it
stops is the *relay* — which the user never chose to trust with this — making
the decision.

Note this narrows the blindness above slightly and deliberately: the relay learns
framing and volume, never content. For **Open** communities that distinction
matters, because the content is not E2EE — the client's session with the host
must therefore be encrypted end-to-end *through* the relay regardless of tier,
which is exactly what the nested TLS above provides.

### 3.3 Server-to-server is store-and-forward only

Servers talk to each other in exactly one situation: handing a DM to the
recipient's home server (§3.4). Nothing else crosses a server boundary.

**What this is not.** Matrix's difficulty comes from multiple servers holding
authoritative copies of *shared mutable state* and having to converge — that is
where state resolution, and most of the protocol's complexity, comes from. Veil's
server-to-server surface is one-way delivery of immutable opaque blobs into a
mailbox. No shared state, no convergence, no conflict resolution, closer to SMTP
relaying than to federation.

The simplification that matters therefore survives: **communities never
replicate.** A community lives on one host, and clients reach it through their
relay. Server-to-server is confined to DM delivery and must stay there — the
moment it starts carrying community state, state resolution comes back and the
architecture's main advantage is gone.

**Transport reuses existing machinery.** A sending server authenticates to a
receiving server with the same signed handshake and envelope as a client
(§4.3, **[built]**), presenting a server identity instead of a user identity.
Little new protocol surface.

### 3.4 DMs use a mailbox model

A client only ever connects to **its own home server**, in both directions:

1. Alice's client hands the message to **her** home server.
2. Her server forwards it to **Bob's** home server, queueing and retrying if that
   server is down.
3. Bob's server holds it in his mailbox and delivers when he next comes online.

**Why not have the client deliver directly.** An earlier draft had Alice's client
connect to Bob's home server through her relay. That avoided server-to-server
entirely, but it broke in two ways. Twenty DM partners meant twenty destinations
and twenty tunnels — untenable on mobile, where you cannot hold that many
connections and would pay connection setup on every conversation. And it let *any
client* deposit into *any* mailbox, which is an unrate-limitable spam vector.

Routing through home servers fixes both. The client holds one connection. And
deposits now arrive server-to-server, so they are rate-limited per sending
server — a known entity with standing (§11.4) — which is exactly how mail handles
the same problem.

**Device lists work the same way.** Alice's home server fetches and caches Bob's
device list rather than her client reaching for it. That server cannot lie about
the contents: cross-signing (§5.4) means Alice verifies every device against
Bob's SSK and MSK, so a substituted or omitted device is detected.

Bob's home server learns that Alice messages Bob and when. Content is E2EE and
unreadable to it, and Alice's IP is never exposed to it, since her server is the
one connecting.

**"Bob's home server" is really an ordered list.** A user publishes several
servers that accept mail for them; the sender tries them in priority order and
delivers to the first that answers, with backups forwarding onward once the
primary recovers. See §11.6 — it changes the delivery path but nothing else about
this model.

### 3.5 Direct connection as a fallback

If a user's home server is down, they are otherwise cut off entirely. Clients
should permit direct connection to a host as an explicit, per-session choice
with a plain warning that it exposes their IP. Stranded users will otherwise
route around the system in worse ways.

### 3.6 Protocol versioning

Anyone can run a server, so **version skew is the normal state, not an edge
case**. Operators run whatever they installed two years ago, and a protocol with
no negotiation story fragments the network the first time it changes.

Each side supports a contiguous **range** of protocol versions and advertises it
during the handshake. The agreed version is the highest both support:

```
agreed = min(client.max, host.max)
if agreed < client.min || agreed < host.min { refuse to connect }
```

**Advertise a range, not just a maximum.** Comparing maxima alone works only
while everyone supports every version back to 1 — and old versions get dropped
for exactly the reasons that produced new ones. A client supporting 3–5 meeting a
host supporting 1–2 must fail cleanly, not "agree" on 2 that the client cannot
speak.

#### The negotiation must be signed

This is the part that is easy to get wrong and expensive to get wrong. If an
attacker can edit the advertised ranges in flight, they force both sides onto the
oldest mutually supported version and attack that instead — the downgrade family
that produced FREAK, Logjam, and POODLE against TLS.

Veil is well placed here because **the handshake is already signed** (§4.3,
**[built]**). Both advertised ranges go into the signed transcript, so tampering
breaks signature verification rather than silently succeeding. Fold the ranges
into `signing_input` when the handshake gains version support; do not add a
separate unsigned exchange in front of it.

#### Communities carry a minimum version

Negotiation covers client-to-host. It does not cover a community using features a
host is too old to serve, so a community carries a `min_version` as a signed
`VersionRequirement` record in its policy chain (§7.4). A host below it refuses to
serve the community rather than serving it wrongly.

It lives in the chain rather than in `CommunityRoot` for a specific reason: the
root is hashed into the `CommunityId` and so can never change. A `min_version`
frozen at creation could never be raised, which would strand every existing
community on the version it was founded with.

#### Deprecation is a §1.3 concern

Dropping an old version cuts off every self-hoster who has not updated, which is
the §1.3 invariant failing quietly rather than loudly. So the support window is a
stated policy, not an implementation detail: **support at least the previous two
major versions, for a minimum of two years**, and surface an in-app warning well
before a version stops being served.

Note the relay is unaffected — it validates TLS records (§3.2) and never parses
protocol frames, so relays need no updating when versions change. That was the
point of the framing decision.

---

## 4. Threat model

### 4.1 Sealed tier (E2EE)

**Protected against:** the community host reading content; the home server
reading content; a network attacker reading or modifying anything; protocol-level
impersonation; replay of captured frames; the community host learning the user's
IP.

**Not protected against:** a compromised endpoint device; metadata (§14); a host
refusing service or dropping messages.

### 4.2 Open tier (server-readable)

**Protected against:** a network attacker; the *home server* reading content
(blind relay, §3.2); protocol-level impersonation; unauthorised access to stored
data (§7.5); the community host learning the user's IP.

**Explicitly trusted:** the community host operator, who can read all content in
their own community. Exactly one party, chosen by the user when they joined.

### 4.3 Cross-cutting

No server is trusted to assert *identity*. Users are identified by
self-certifying IDs (§5.1) and verified by cross-signing (§5.4), so neither a
home server nor a community host can substitute keys for a peer.

Home server attestations (§11.2) are an *abuse* mechanism, not an identity one.
A home server can refuse to vouch for a user; it cannot forge who they are.

---

## 5. Identity model

The most important section. **Multi-device is fully supported by the design
below** — devices are first-class objects under a user (§5.2), trusted via
cross-signing (§5.4), and enrolled by approval from an existing device which then
hands over history (§12.5).

> **What exists today is a different story, and this paragraph is about the
> shipped code, not the design.** In the current implementation identity *is* the
> device: one `State`, one Olm `Account`, and the server routes on
> `account.ed25519_key()`. Two clients sharing a profile do not federate — the
> second silently overwrites the first in the routing map. So multi-device is not
> merely unimplemented, the present keying actively prevents it. That is precisely
> why §5.1–5.3 is Tier 1 item 1 (§15): it cannot be bolted on later without
> rewriting every stored session and every peer's pinned trust.

### 5.1 User identity

A user owns a long-lived **master key** (MSK, ed25519) and a stable **`UserId`**
derived from it:

```
UserId = base32( SHA-256( "veil-user-id-v1" || MSK_public ) )   // truncated to 128 bits
```

Self-certifying: anyone holding a `UserId` can verify a presented MSK matches it,
with no server involvement. No server can map a `UserId` to different key
material than its owner published.

**Crucially, the `UserId` contains no hostname.** A user is not bound to their
home server and can move without becoming a different person — the single worst
structural problem with Matrix's `@user:server` scheme. Portability is preserved
by making the *attestation* (§11.2) swappable while the identity stays fixed.

Rotating the MSK changes the `UserId`. That is intentional: it is the root of
identity, and rotating it should be a visible, disruptive event requiring peers
to re-verify. Routine compromise is handled by rotating a *device* key (§5.5).

Display names live in a separate mutable layer that servers can lie about. That
is acceptable because names are not a security boundary — safety numbers (§6.1)
are.

### 5.2 Device identity

```
Device {
  device_id:         [u8; 16],   // random, stable for the device's life
  ed25519_public:    [u8; 32],   // signing
  curve25519_public: [u8; 32],   // Olm identity key
  one_time_keys:     Vec<[u8; 32]>,
  fallback_key:      [u8; 32],
  ssk_signature:     [u8; 64],   // proves the device belongs to the user
  display_name:      String,
  created_at:        u64,
  last_seen:         u64,
}
```

Olm sessions are established **device-to-device**, never user-to-user. A message
to a user is encrypted separately for each of that user's active devices.

### 5.3 Routing addresses

Routing addresses `UserId` and `(UserId, device_id)` — never raw key material.
This is what makes rotation possible at all: today the routing address *is* the
ed25519 key, so a user cannot rotate without becoming a different user.

### 5.4 Cross-signing

Three keys per user, following Matrix's proven structure:

| Key | Signed by | Signs | Purpose |
| --- | --- | --- | --- |
| **MSK** master | self | SSK, USK | root of identity; kept cold |
| **SSK** self-signing | MSK | this user's own devices | day-to-day device enrolment |
| **USK** user-signing | MSK | *other users'* MSKs | records "I verified this person" |

Three keys rather than one so the MSK stays cold: adding a device uses the SSK,
and the MSK is only needed to establish or rotate the signing keys themselves.

**The UX payoff.** Alice verifies Bob *once* by comparing safety numbers of their
MSKs. Alice's USK then signs Bob's MSK. From then on every device Bob owns —
including ones he adds later — is trusted automatically, because Bob's SSK signs
his devices and his MSK signs his SSK. Verify the person, not each device.
Per-device verification does not survive contact with real users.

**Verification chain** a client walks before trusting a device:

```
device.ssk_signature  ->  SSK
SSK.msk_signature     ->  MSK
MSK                   ->  hashes to the claimed UserId     (self-certifying)
MSK                   ->  signed by our USK?               (have we verified them?)
```

A device failing this chain is shown as unverified and its messages marked. It is
not silently accepted.

### 5.5 Key rotation

- **Device key** — device generates new keys, SSK signs them, publishes. Cheap,
  routine, invisible to peers. The answer to a suspected device compromise.
- **Subkey (SSK or USK)** — master signs a replacement. **Currently has no
  rollback defence**: nothing in a published key set says how recent it is, so a
  device still holding an old set could reinstate it, and devices enrolled under
  the new subkey would then fail verification. If the subkey was rotated *because*
  of a compromise, the attacker holds exactly such a device. Needs a monotonic
  marker on the key set before subkey rotation is safe to rely on.
- **Device removal** — user removes it from their list and re-signs. Forces
  Megolm rotation in every Sealed group they belong to (§8.3).
- **MSK** — changes the `UserId`. All peers must re-verify, and see an explicit
  "this user's identity changed" warning, in the spirit of Signal's
  safety-number-changed alert. Rare and deliberately disruptive.

---

## 6. Trust establishment

### 6.1 Safety numbers **[primitive built]**

`safety_number(a, b)` derives a 30-digit code from a sorted pair of identity
keys, so both peers compute the same value without agreeing on an ordering.
Reading it aloud over a channel the attacker does not control closes the
trust-on-first-use gap.

It currently operates on raw ed25519 identity keys. Under §5 it must operate on
**MSKs**, so one comparison covers the user's whole device set via cross-signing.

### 6.2 Trust on first use

First contact pins the peer's MSK. A later change is refused, not silently
accepted, and surfaces as an explicit warning. The same already applies to the
server's identity key **[built]**.

---

## 7. Encryption tiers

Two modes. The split exists because E2EE and Discord's feature set are in
genuine conflict: server-side search, moderation, spam filtering, bots reading
channel content, push previews, and instant history for a new device all require
the server to read content.

### 7.1 The two tiers

| | **Sealed** | **Open** |
| --- | --- | --- |
| Content encryption | E2EE (Olm / Megolm) | TLS in transit, encrypted at rest |
| Host can read | no | yes |
| Practical size | 1:1 to a few hundred | unbounded |
| Search | client-side only | server-side |
| Moderation, bots | very limited | full |
| New-device history | limited | full |

**Defaults:** DMs, group chats, and calls are Sealed, always. Communities are
Open by default, with Sealed offered.

Sealed communities are expected to be **rare**. If the host operator is also a
member — the normal case for a self-hosted community — encrypting against them
achieves nothing. Hiding from the owner is not the reason to pick Sealed.

**The real reason is durability, not privacy.** Because a Sealed community's
database is ciphertext, it is safe to hand a complete copy to *any* member
(§12.3). The host degrades to an untrusted blob store, and blob stores are
replaceable. A Sealed community can therefore outlive its operator with no
cooperation from them, while an Open one depends on its admin set.

So the tier choice is not privacy versus features. It is **durability and
privacy versus features**, and that is the line the UI should use: *"this
community can outlive me."*

There is no protocol-enforced member cap. Sealed's practical ceiling comes from
Megolm rotation cost (§8.3), and a community that outgrows it converts (§7.3)
rather than hitting a wall.

### 7.2 Mode is a property of the container

Channels inherit their community's mode. **No mixed-mode communities.** A user
cannot track which channel is safe, and the mental model collapses the first
time they are wrong. One mode per container, inherited by everything inside it.

### 7.3 Mode transitions are one-way and non-retroactive

An earlier draft made mode strictly immutable. That was over-corrected: it forces
an irreversible decision at the moment the founder has the *least* information
about eventual size, with bad outcomes on both sides — pick Sealed and outgrow
it, and the community is stranded with no path out but abandonment.

The property actually worth protecting is that **content never becomes readable
after being disclosed under an encrypted guarantee.** A forward-only transition
preserves that:

- **Sealed → Open only.** Never the reverse; you cannot retroactively promise
  protection for history that is already readable.
- **Non-retroactive.** Megolm keys for the Sealed era are never uploaded, so that
  content stays encrypted permanently. The host cannot read it even after the
  transition.
- **Explicitly consented, permanently marked, members notified.**
- **The host cannot do it unilaterally** (§7.4).

The cost is split-era history: search and new-device sync cover only the readable
era. That is comprehensible and worth stating in the UI.

### 7.4 Mode is cryptographically bound

If the host declares a community's mode, a malicious host declares a Sealed
community Open and reads everything. The mode therefore lives inside the
community's identity, and transitions extend a signed chain:

```
CommunityRoot {
  mode:              Sealed | Open,   // mode at creation
  controllers:       Vec<[u8; 32]>,   // authorises transitions and succession
  threshold:         u8,              // k of n required
  founder_user_id:   UserId,
  created_at:        u64,
  founder_signature: [u8; 64],
}

CommunityId = base32( SHA-256( "veil-community-v1" || canonical(CommunityRoot) ) )

ModeTransition {
  community_id:  CommunityId,
  new_mode:      Open,                // Sealed -> Open only
  sequence:      u64,                 // monotonic; blocks rollback replay
  signatures:    Vec<[u8; 64]>,       // >= threshold, from distinct controllers
}

VersionRequirement {
  community_id:  CommunityId,
  min_version:   u16,                 // hosts below this refuse to serve (§3.6)
  sequence:      u64,
  signatures:    Vec<[u8; 64]>,
}
```

**Anything mutable lives in the chain, never in the root.** The root is hashed to
produce the `CommunityId`, so every field in it is frozen for the community's
life. A minimum protocol version placed there could never be raised — a community
founded on v1 could never adopt a v5 feature. The same reasoning applies to any
future policy field: if it might ever change, it is a signed chain record with a
monotonic `sequence`, not a root field.

**Controllers are k-of-n, not a single key.** A lone controller key is held by
exactly the person most likely to disappear, which makes the community's
governance die with its operator. A threshold over the admin set lets the
remaining admins act (§12.4).

Clients verify the root hashes to the `CommunityId` they hold, then replay the
transition chain, on join and on every reconnect. A host presenting a mode not
backed by a valid signed chain is refused.

This is the easiest thing in the design to get wrong. Getting it wrong means
shipping a protocol where the operator can switch encryption off.

### 7.5 Open-tier obligations

"Just use TLS" is transport only. Once the host reads plaintext the threat model
flips from *the server cannot read this* to *the server is trusted, so it must be
defended*:

- encryption at rest for content and attachments, **including backups** (§12.3)
- key management for those at-rest keys, not a config-file constant
- access control and audit logging on operator tooling that can read content
- a documented retention and deletion policy
- breach planning proportionate to a breach exposing everything in the tier

### 7.6 Moderation in a Sealed community

The host cannot read content, so moderation works differently rather than not at
all. **Removing a person works; removing a piece of content does not.**

#### Reporting

The reporter's client already holds the plaintext, so it decrypts the message in
question and submits it. To stop a reporter fabricating quotes, the report can
carry cryptographic attribution, because the pieces already exist:

- the original envelope, **signed by the sender's device key** (§4.3)
- the Megolm session exported *at that message's index*, which vodozemac supports

The host verifies the signature, decrypts with the exported key, and confirms the
plaintext matches. That is proof of authorship, not an accusation.

Caveat worth knowing: a Megolm session exported at index *N* decrypts everything
from *N* forward in that session, so a verifiable report reveals somewhat more
than the single message. Reports without attribution should therefore be accepted
too and treated as **signal for human review** rather than proof — which is what
mainstream platforms do with reports regardless.

#### What an operator can and cannot do

| Action | Sealed |
| --- | --- |
| Remove a member | yes — membership change forces Megolm rotation (§8.3) |
| Ban an identity from rejoining | yes |
| Delete a specific message for everyone | **no** — cannot identify it |
| Scan proactively for illegal content | **no** |
| Remove an entire community | yes |
| Hand over readable content on demand | **no** |

#### The operator's legal position

**Not legal advice, and jurisdiction changes the answer substantially.** But "I
cannot comply, therefore I am not liable" is a weaker position than it sounds,
and anyone running a public Sealed community should know that before they start.

The recurring pattern is that **courts do not accept "I can't" — they order
something you *can* do, which is usually worse.** Lavabit could not produce one
user's mail without its TLS key, so the court ordered the key for the entire
service; refusing produced contempt and fines, and the service shut down. In
*Apple v. FBI* the government sought to compel Apple to *write* software it did
not have. The UK Investigatory Powers Act allows technical capability notices
that require a provider to remove electronic protection or to become able to —
inability is not a defence, it is the thing the notice orders you to fix.
Australia's Assistance and Access Act is similar.

Two further exposures specific to this architecture:

- **Metadata is not protected by content encryption.** Home servers hold who
  talks to whom and when (§14). Retention and disclosure orders reach that
  regardless of Sealed, and home servers are the natural target precisely because
  they hold it.
- **Safe-harbour regimes generally require acting on notice.** An operator who
  cannot remove specific content may be pushed to the blunt remedy — removing the
  whole community — to stay within them.

The design implication is to make sure the blunt instruments exist and are
documented, so an operator always has *something* they can do: remove a member,
remove a community, and shut down cleanly. An operator with no available action
is in a far worse position than one with a drastic one.

**Data minimisation is therefore a legal strategy, not only a privacy one.** You
cannot be ordered to produce what you never retained; §14 should be read with
that in mind.

---

## 8. Group messaging — Sealed tier

### 8.1 Megolm

Per-sender, per-channel ratcheting group sessions. The sender encrypts each
message once; recipients decrypt with the matching inbound session. Content
encryption is O(1) in group size.

### 8.2 Key distribution

The Megolm session key is distributed **pairwise over Olm**, once per recipient
*device*:

```
distribution cost per rotation  =  Σ (devices per member)
```

A 500-member channel at ~2 devices each is ~1000 Olm encryptions per rotation.

### 8.3 Rotation and the churn problem

Rotation is mandatory on **member removal** — otherwise the removed member keeps
decrypting — and additionally triggered by message count and elapsed time.

The binding constraint is **churn × devices**, not membership. Communities with
constant joins and leaves pay continuously. This is exactly why large
communities default to Open: it keeps Megolm confined to groups where fan-out is
bounded, and the cliff never appears on the critical path.

Joins require no rotation — a joiner receives the current key and by construction
cannot read history from before they joined.

### 8.4 Keeping the layer swappable

```rust
trait GroupKeyProvider {
    fn encrypt_for_group(&mut self, channel: ChannelId, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_for_group(&mut self, channel: ChannelId, sender: DeviceRef, ct: &[u8]) -> Result<Vec<u8>>;
    fn on_membership_change(&mut self, channel: ChannelId, change: MembershipChange) -> Result<()>;
    fn on_device_change(&mut self, user: UserId, change: DeviceChange) -> Result<()>;
}
```

If churn cost forces the question, **MLS (RFC 9420, via OpenMLS)** replaces one
module instead of the stack. MLS scales key agreement logarithmically and is what
Discord's own DAVE protocol uses for voice. Adopting the boundary now is nearly
free; retrofitting it is not.

### 8.5 Roles and permissions under Sealed

Roles are a Tier 3 feature, but one aspect of them reaches back into Tier 1 and
must be settled before key distribution is built.

#### Only *read* needs cryptographic enforcement

In Open, every permission is an ACL the host checks. In Sealed the host is
untrusted for content, so the instinct is that all permissions need cryptographic
backing. They do not:

| Permission | Enforced by |
| --- | --- |
| **Read a channel** | **Cryptography** — you either hold the Megolm key or you do not |
| Send, kick, ban, pin, manage, invite | The host, as an ordinary ACL |

Everything except reading is an *action the host can simply refuse*: it declines
the message, declines the kick, declines the rename. A host that ignores its own
ACL is misbehaving in a way members can observe. Reading is the one permission a
host cannot claw back after the fact, so it is the only one that has to be
enforced by key possession.

This collapses a Discord-sized permission matrix into one cryptographic question:
**who holds the key for this channel.**

#### Read-permission changes are expensive; everything else is cheap

Because read access *is* key possession, revoking it means rotating the channel's
Megolm session and redistributing to everyone remaining (§8.3). So:

- removing someone from a role that granted read access = a rotation per affected
  channel
- changing who may pin messages, or rename a channel = a database write

The UI should reflect this asymmetry rather than hide it. Restructuring read
access in a large Sealed community is a heavyweight operation, and presenting it
as equivalent to any other permission toggle sets up a nasty surprise.

#### Role state must be signed, not host-asserted

This is the part that constrains Tier 1. **Senders decide who receives Megolm
keys**, so a sender must know the channel's authorised reader set. If that set is
whatever the host claims, a malicious host adds an attacker and every sender
dutifully encrypts to them — defeating Sealed without touching a single message.

So role and channel-membership state lives in the **signed policy chain**
(§7.4), alongside mode transitions and version requirements: controller-signed,
monotonically sequenced, and verified by every client before it distributes keys.
The host serves the chain; it does not author it.

Practical consequence for §8.4: `on_membership_change` must be driven by
*verified chain state*, never by a host notification. A `GroupKeyProvider` that
trusts the host about membership is a `GroupKeyProvider` that can be told to leak
keys.

---

## 9. Calls and real-time media

**Revised after implementation.** An earlier draft of this section said calls
need SRTP with per-frame keying, an SFU forwarding streams it cannot decrypt, and
that "MLS is effectively unavoidable" — and concluded they were foundational work
rather than a feature. That is true of the *large* case and was wrongly applied
to all of them. Sizing every call by the hardest one put a second cryptographic
protocol on the critical path for a two-person voice call, which needs none of
it.

Three tiers, and only the first is needed for calls to exist.

| Participants | Transport | New cryptography |
| --- | --- | --- |
| **2** | direct or relayed, stock WebRTC | **none** |
| **3–5** | full mesh | **none** |
| **many** | SFU + SFrame | a group key — Megolm first, MLS if churn demands it |

**A 1:1 call needs nothing new.** WebRTC's DTLS-SRTP is already end-to-end
between two peers. What makes that MITM-able is unauthenticated signalling — and
Veil already has an authenticated channel, because an Olm session runs to a
device verified through cross-signing (§5.4). The SDP carries the DTLS
fingerprint, so sending it over that session authenticates the media keys with no
new PKI. This is how Signal handles 1:1, and it is the load-bearing simplification.

**Small groups are the same primitives, meshed.** Every participant holds a
session with every other. There is no SFU, so there is nothing in the middle to
keep out of the trust set — mesh is *more* private than an SFU, it simply does
not scale. §9.1's own figures make the case: voice is 50–64 kbps and most
participants are muted, so a four-way voice mesh is around 200 kbps upstream.
Video mesh dies at about four people, and that is the honest limit.

**MLS is an optimisation, not a prerequisite.** When an SFU does land it needs a
group key for SFrame, and `GroupKeyProvider` (§8.4) already provides one — that
boundary exists so the implementation can change without the stack changing.
Megolm rekeys in O(n) pairwise encryptions, which for a fifty-person call is
fifty Olm operations and takes milliseconds. MLS earns its place when churn is
high enough that O(log n) matters, and the trigger for reconsidering is churn
rate, not participant count.

**What must not be simplified.** Signalling travels over the authenticated
encrypted channel, always. Route SDP through a plaintext or server-mediated path
and the fingerprint can be swapped in flight, which undoes every layer above it.
That is where the guarantee lives.

### 9.0 Where the performance is

Not in the encryption, and it is worth being concrete because the assumption is
common. SRTP is AES-GCM over a ~160-byte payload: tens of nanoseconds against a
20 ms packet interval, so roughly a millionth of the budget. An encrypted call
and a plaintext one differ by nothing a person could hear.

What people hear is latency and jitter, which come from four places:

1. **The jitter buffer**, the largest lever. Every millisecond held is a
   millisecond added to the conversation; every millisecond not held is a chance
   to run dry. Veil's adapts to observed arrival spread rather than picking a
   constant, because the right depth on a wired connection and on a train differ
   by an order of magnitude and a constant chosen for the worst case makes every
   good connection feel bad. Floor of two packets, ceiling of twenty-five —
   past about half a second people talk over each other, so dropping audio
   becomes the better failure.
2. **Packet loss concealment.** A gap must play as silence of the right length
   rather than a skipped instant, or speech runs fast and the pitch wanders.
3. **Allocation.** Fifty packets a second per stream means a per-packet
   allocation is fifty pointless trips to the allocator every second; the buffer
   reuses its storage.
4. **The relay hop**, which is the one the user can trade away — with both
   parties' consent, per call (§9.1).

#### Existing libraries do the parts that should not be written twice

**cpal** for devices and **libopus** for the codec. Neither is a place to be
original: cpal is what most Rust audio stands on, and libopus is what every
WebRTC endpoint already negotiates. Veil's contribution is the authenticated
signalling in the middle, and everything either side of it should be ordinary.

Three details that are not arbitrary:

- **20 ms frames, 48 kHz, mono.** The frame length matches the packet interval,
  because a codec frame and a network packet should be the same thing —
  mismatched, every packet either splits a frame or carries two. Mono because
  §9.1's figures assume voice, and stereo doubles the cost to convey nothing a
  conversation needs.
- **Concealment is the codec's, not silence.** When the buffer reports a gap,
  Opus generates a frame that continues the waveform. Silence sounds like a
  hole, and a listener hears the difference at one lost packet in a hundred.
- **Audio owns its own thread.** Callbacks have a hard deadline, and `cpal`'s
  streams are not `Send` — so they live on a dedicated thread and talk to the
  async world over channels. Neither callback allocates or blocks.

**A machine with no sound card still runs the client.** It places and answers
calls and is told it has no audio, rather than being refused something it could
otherwise do — which is the ordinary case on a server or in a container.

### 9.1 Transport: relayed by default, P2P by choice

Media is relayed through the user's home server by default, for the same reason
as §3.2 — a call should not hand your IP to whoever you are talking to. The home
server acts as a TURN-style relay for its users. The bandwidth cost is real and
is the price of the property.

**P2P is offered as an explicit per-call escalation**, surfaced when quality is
poor — a laggy game stream to a friend is a legitimate reason to take the trade,
and the UI should present it as one rather than hiding it.

Constraints:

- **Both parties must consent.** P2P exposes both IPs; the person with the bad
  connection cannot make that choice for the other.
- **Per-call, never sticky.** A preference that carries silently into a call with
  a stranger is a security failure.

#### Bandwidth: voice is cheap, video is not

Relay cost is dominated by video and screenshare, not voice, and the difference
is two orders of magnitude:

| Stream | Sustained rate |
| --- | --- |
| Voice, active speaker | ~50–64 kbps |
| Voice, muted | ~0 (voice activity detection sends nothing) |
| Video | ~1–3 Mbps |
| Screenshare, 1080p60 | ~3–8 Mbps |

So a 50-person voice channel is unremarkable — most participants are muted and
send nothing, and only a handful of active speakers cost anything at all. A
handful of screenshares on the same box is what saturates a domestic uplink.

This is why the P2P escalation above is scoped the way it is: the expensive case
and the case where users least mind exposing an IP — streaming a game to a
friend — are the same case.

Two further mitigations before "upgrade your connection":

- **Selective forwarding.** The SFU forwards only streams a receiver is actually
  displaying. Nobody watching a stream means nobody paying to relay it.
- **Simulcast.** Senders publish several qualities; the SFU forwards the lowest
  one adequate for each receiver, rather than the highest for all.

Together these make large voice channels essentially free to relay and keep video
costs proportional to what is actually being *watched* rather than published.

---

## 10. Message model

Identical across both tiers. Only `content` differs: opaque ciphertext in Sealed,
structured readable data in Open.

```
Message {
  // --- authored and signed by the sending device ---
  channel_id:  ChannelId,
  sender:      (UserId, device_id),
  nonce:       [u8; 16],
  origin_ts:   u64,        // client clock, untrusted
  seen_head:   [u8; 32],   // message_id of the latest message the sender had seen
  content:     Payload,    // ciphertext | structured

  // --- assigned by the host on accept ---
  seq:         u64,        // monotonic per channel
  prev_hash:   [u8; 32],   // message_id of seq-1 in this channel
  server_ts:   u64,        // authoritative for ordering
}
```

**Why now.** Edits, replies, reactions, threads, pagination, and read receipts all
reference prior messages. Adding identity and ordering after stored history
exists means migrating every stored message and every reference. The cost today
is a struct definition.

- **`message_id` is content-addressed and *derived, not transmitted*.** It is
  `H(sender || origin_ts || nonce || content)`, as Matrix event IDs are from room
  version 4 onward, so any change to the message changes its identity. Carrying
  it on the wire would only let a sender claim an id disagreeing with its
  content, and every receiver has to recompute it to check anyway — computing it
  is strictly less to go wrong. The `nonce` keeps two identical messages
  distinct; a retry reuses it, so idempotency and dedup still work.
- **Duplicate suppression is separate from replay defence.** `ReplayGuard` stops
  a captured *envelope* being re-sent; a bounded window of seen `message_id`s
  stops the same *message* being processed twice. That second one matters
  because decrypting twice advances an Olm ratchet for something already
  handled, and ordinary retries cause it far more often than attacks do.
- `seq` is host-assigned because clients cannot be trusted to order honestly.
- `seen_head` is **sender-attested and inside the signed envelope** (§10.1).
- In Sealed, reply and reaction *targets* live inside the ciphertext so the host
  does not learn thread structure. Reaction aggregation therefore happens
  client-side. Accepted deliberately.

**The split above is the important part.** Members author and sign the top half.
The host owns the bottom half and is the sole writer of the log: it assigns
order, computes the chain, and propagates. **A member cannot write, reorder, or
rewrite anything** — a member's only power over history is *read-side*: holding
a copy and being able to prove what it says.

#### Channels are sequenced; DMs are not

The host-assigned fields only exist where there is a host to assign them.

- **Community channels** — one authoritative host, so `seq`, `prev_hash`, and
  `server_ts` are assigned and the channel is a totally ordered log (§10.1).
- **DMs** — no shared log to sequence. A conversation's messages live in *two
  different mailboxes*, one per participant (§3.4), so no single server ever sees
  both sides. Ordering is client-side, from Olm's per-session message indices
  plus `seen_head` for causal order. With two participants there is no meaningful
  ambiguity to resolve.

This is not a consequence of fallback mailboxes (§11.6) — it holds even with a
single mailbox each, because the split is inherent to per-recipient delivery. It
is also what makes fallback mailboxes safe to have: with nothing to sequence,
mailboxes are unordered bags of messages and need no consistency between them.

### 10.1 Integrity: the hash chain and sender attestation

Two mechanisms, borrowed from Matrix and adapted to a single-host architecture.

**The chain (host-built).** `prev_hash` makes each channel an append-only chain
rather than a bag of rows, so a member's partial history is a *verifiable*
fragment rather than a claim, and a restored or forked host cannot rewrite what
members hold. This is what makes a git repository effectively unkillable — every
clone is a verifiable copy, and promoting one to origin is a social decision, not
a technical one. It is why §12.4 can treat an unsigned fork as a legitimate last
resort rather than a forgery risk.

**`seen_head` (sender-attested).** This is Matrix's `prev_events`, used for
*evidence* rather than for ordering. When Alice sends, she names the latest
message she had seen. Because it sits inside the device-signed envelope, the host
cannot fabricate or alter it.

The distinction matters: the chain is built by the party you are trying to hold
accountable, whereas `seen_head` is authored by someone who is not. That is what
makes equivocation detectable at all.

#### What Matrix does, and why we cannot copy all of it

| Attack | Matrix | Veil |
| --- | --- | --- |
| **Rewrite** | Caught, strongly — content-addressed IDs plus *N* replicas that disagree | Caught, if a member kept a copy |
| **Omit at write time** | **Not caught** — the origin server simply never authors the event | Not caught — same gap |
| **Reorder** | Largely caught — `prev_events` is authored sender-side | Caught by `seen_head`, same mechanism |
| **Equivocate** | Caught *across servers*; your own homeserver can still lie to you | Caught across members, by comparing attested heads |

**Most of Matrix's strength here comes from replication, not from the DAG.** The
independent witnesses are what make rewriting and equivocation detectable, and
§3.1 removed replication deliberately. Copying the DAG shape alone would not
inherit the property.

So the substitution is: **in Matrix the witnesses are homeservers; in Veil they
are members.** Member-held copies (§12.3) are the replica set, and `seen_head` is
what turns those passive copies into an active detection network. There are more
members than there would be homeservers, so the witness population is arguably
better distributed — but it degrades in a specific way worth knowing: a channel
where one person talks and nobody else is online has no witnesses at that moment.
Matrix has the identical weakness in a room with only one homeserver present.

#### Where Veil is already stronger than Matrix

Matrix events are signed by the **originating homeserver**, not by the user's
device — so a malicious Matrix homeserver can forge events attributed to its own
users. Veil envelopes are **device-signed** (§4.3, **[built]**), so authorship is
provable against the user rather than their server.

Do not regress this while copying anything else. It is a genuine improvement.

#### What the chain does and does not catch

A client cannot compute `prev_hash` itself: it does not know its `seq` until the
host assigns one. The host therefore builds the chain, and that bounds what the
chain proves. Four distinct attacks, and they are not equally covered:

| Attack | Caught by the chain? |
| --- | --- |
| **Rewrite** — alter a past message | Yes — chain, if any member holds a copy |
| **Reorder** — assign `seq` to change meaning | Yes — `seen_head` contradicts the claimed order |
| **Equivocate** — show different history to different members | Yes — attested heads cannot be reconciled |
| **Omit** — silently drop a message at write time | Partially — only with receipts, below |

**Rewriting** is what the chain handles, and it is why §12.4 can treat an
unsigned fork as a last resort rather than a forgery risk. Coverage is only as
good as who kept a copy: messages every client has pruned are unprotected,
because nothing remains to disagree with.

**Reordering and equivocation** are what `seen_head` handles. A host maintaining
two chains — one shown to Alice, another to Bob — produces views that are each
internally consistent, so neither member can tell alone. But their *attested
heads* are signed statements the host did not author, and two members' heads for
the same `seq` cannot both be reconciled against one chain. The contradiction is
the proof.

> **False accusation is bounded.** A member could lie in `seen_head` to make an
> honest host look guilty. This is weak: the host can present a single
> self-consistent chain containing both attested heads, and a head that appears
> nowhere in it is simply the accuser's fabrication — signed by their own device.
> Genuine equivocation is exactly the case where no such chain exists.

**Omission stays open, deliberately.** Matrix does not solve it either — an
origin server that simply never authors an event leaves nothing downstream to
miss. Signed receipts were considered and **rejected**: a host that wants someone
gone can just refuse their connection, so "accept, acknowledge, then silently
drop" is an odd amount of effort to defend against at the cost of a signature on
every message.

What is worth building instead is free: **the sender already knows what it
sent.** A client can check whether its own messages appear in the history it
fetches back, with no receipt and no signature. That catches deliberate dropping
*and* the far more common case of a bug or a lost write, which makes it a
reliability feature rather than only a security one.

Nothing here makes the host unable to censor. **It cannot be made unable — it is
the single authority (§3.1), and §4.1 lists dropping messages as out of scope.**
What these buy is that misbehaviour leaves evidence, which for a community that
can fork (§12.4) is most of what matters in practice.

#### Sealed resists *targeted* tampering better

Same mechanisms, different practical exposure. In Open the host reads content, so
it can drop or reorder surgically — the one message it dislikes. In Sealed it
cannot see what it is dropping, so censorship is limited to blunt selectors:
sender, timing, volume. Dropping "that message" requires knowing which one it is.

#### Why `seen_head` and not a full DAG

Matrix uses `prev_events` for *ordering*, which makes the room a DAG and forces
divergence handling and merge rules — state resolution, the complexity §3.3
exists to avoid.

Veil uses the same attestation for *evidence only*. The host still assigns a
single total order via `seq`, so there is never more than one chain to reconcile
and no merge semantics are needed. `seen_head` is read by clients to check the
host's honesty, never to compute order.

**This is the deliberate trade: Matrix's integrity mechanism, without Matrix's
ordering problem.** The cost is that evidence is retrospective — it proves
misbehaviour after the fact rather than preventing it — which is the correct
ceiling for a single-authority architecture anyway.

### 10.2 Attachments and media

Attachment encryption **follows the container's tier** and is not a per-file
choice. Sealed communities get end-to-end encrypted attachments; Open communities
get attachments the host can process. This is §7.2 container inheritance applied
to media, and it is deliberate — see below.

#### Sealed: encrypted client-side

The client generates a random key per file, encrypts, uploads the ciphertext as
an opaque blob, and distributes the key inside the Megolm-encrypted message. The
host stores bytes it cannot read.

Consequences, all of which are the host losing the ability to process media:

- **Thumbnails are generated and uploaded by the sender**, as separately
  encrypted blobs. The host cannot make them.
- **No server transcoding**, so no adaptive quality — every recipient downloads
  what the sender uploaded.
- **No deduplication and no CDN-level caching** of anything meaningful, since two
  identical files encrypt to different ciphertexts.
- **Quota enforcement works on opaque sizes only**, which is sufficient.
- **Range requests still work** with a counter-mode cipher, so seeking within a
  large encrypted video is fine.

#### Why not let the uploader choose per file

The tempting version is a per-upload toggle: encrypted, or plaintext for speed.
It should not exist, for two reasons.

**It is a silent downgrade, and one user makes it for everyone.** Bob posts
something sensitive in a Sealed community relying on the guarantee; Alice
uploads a screenshot of it unencrypted because that was faster. Bob's disclosure
decision has been undone by someone else's convenience setting. That is precisely
what §1.2 principle 4 forbids, and the person bearing the cost is not the person
making the choice.

**More practically, encryption is not the bottleneck it is imagined to be.**
ChaCha20 runs at gigabytes per second on current hardware; a 100 MB video
encrypts in well under a tenth of a second. What actually makes Sealed media feel
slower is the *server-side processing* listed above — transcoding, thumbnails,
CDN — none of which a per-file encryption toggle recovers. The toggle trades away
the tier's guarantee to fix a cost that is nearly zero.

**The right lever is client-side pre-processing.** A sender wanting a 2 GB video
to arrive quickly transcodes it locally to several qualities, encrypts each, and
uploads them; recipients fetch the one they need. That costs the sender upload
bandwidth and buys the same adaptive-quality experience with the guarantee
intact. It is what Signal and Matrix both do.

If a per-file choice is wanted anyway, the minimum bar is that it be **visibly
marked to every viewer**, so nobody is misled about what is protected. Silent is
not an option.

### 10.3 Ephemeral events: presence, typing, read state

A client opens a subscription to a room — any shared space to chat — and
membership of that subscription *is* the presence signal. Being there marks
messages read; typing is sent on the same channel.

**Ephemeral events never enter the log.** No `seq`, no `prev_hash`, no place in
the hash chain (§10.1). They are transient by definition, and chaining them would
mean carrying keystroke-level noise in history forever.

#### This is far easier here than at Discord

Presence is notoriously one of the hardest scaling problems in this product
class — but only when it is *global*. Discord must answer "is Alice online?"
across a network of hundreds of millions.

Veil never has to. Presence is scoped to whoever already holds the state:

- **In a community** — the host knows who is subscribed. One community, one host,
  one answer.
- **For DMs** — your home server knows whether you are connected.

There is no cross-community presence and there should not be. "Is Alice online
*somewhere*" would require a global view that no component has, and building one
would mean exactly the central infrastructure §1.3 exists to avoid.

#### Three constraints

**Typing must be rate-limited and scoped to actual viewers.** Broadcasting every
keystroke transition to a 5,000-member channel is O(N²) traffic for a decoration.
Send only to clients currently rendering that channel, and throttle to roughly
one event every few seconds.

**Read state is private by default.** It syncs a user's *own* devices so a
conversation opens in the same place everywhere; it is not broadcast as "Alice
read this." Per-message read receipts visible to others are a separate feature
with real social cost, and should be opt-in if built at all.

**In Sealed, the host learns activity but not content.** Subscription implies
presence, and §12.2's delivery already has clients reporting their last-seen
`seq`, so read position is known to the host regardless. The genuine marginal
leak is fine-grained typing timing — small, and worth stating rather than
discovering.

### 10.4 Search

**Sealed is client-side only, and there is no middle setting.** Giving the host
Megolm keys to build an index does not make search "a bit less private" — it
makes the community *Open*, silently, while still being labelled Sealed. A host
holding the keys can read everything. That is a downgrade §7.3 forbids precisely
because it is invisible to members.

The workable version keeps the index on the client, following Element's design
(Seshat, which wraps the Tantivy full-text engine). **Veil is already Rust, so
Tantivy links in directly** — Element reaches it through a Node native module
from Electron, and we skip that boundary entirely.

#### Making it fast

Query speed is not the hard part. Tantivy is a Lucene-class engine and answers
in single-digit milliseconds over millions of documents. Everything that makes
search *feel* slow is elsewhere:

- **Index at decrypt time, never on demand.** A message is indexed as it comes
  through the receive pipeline, so the index is always current and the cost is
  amortised into work already happening. Search is never "building…".
- **Off the UI thread.** Writes and queries both. Non-negotiable for snappiness.
- **Cold start is the real enemy.** A fresh device with no index must otherwise
  download, decrypt, and index all history before search works at all. This is
  what makes the encrypted index blob load-bearing rather than a convenience —
  restoring it is the difference between instant and a multi-minute wait.
- **Back up incrementally, not wholesale.** Re-uploading a 30 MB index after
  every message is absurd. Tantivy is segment-based, so new segments upload
  individually with occasional merges — the same shape as an append-only log.

Index size runs roughly 20–50% of the underlying text, so a million text
messages lands in the tens of megabytes. Comfortable on desktop, bounded on
mobile.

**Encrypt the index on disk, not just the backup.** A plaintext local index would
undo Sealed for anyone who takes the device — it is a searchable copy of every
message. Seshat encrypts its store for exactly this reason.

#### Mobile stays partial

A phone will not hold years of history, so it indexes a bounded window — recent
months, or a message cap. Searching beyond it is an explicit action that streams,
decrypts, and scans older history with visible progress. Slower, honest, and
still better than nothing.

Remaining limits: a device searches only what it has, and a new device is blank
until it restores. This is a real and permanent gap versus Open.

*Not viable:* searchable symmetric encryption, where a server answers queries over
an encrypted index. Practical schemes leak access patterns, and there is a solid
literature recovering queries and content from that leakage. Not production-ready
for this threat model.

**Open tier has none of these problems** — server-side indexing, instant, complete,
works on a fresh device. That asymmetry is the tier trade working as intended, and
it is one of the better honest arguments for choosing Open.

### 10.5 Deletion and erasure

**Durability and deletion are in direct tension, and this design chose
durability.** Member-held copies (§12.3) are what make a community outlive its
operator — and they are equally what make "delete this everywhere" impossible to
guarantee. That trade was made deliberately; what follows is being honest about
its consequences rather than pretending they do not exist.

#### The chain survives deletion, by construction

Deleting a message must not break the hash chain (§10.1), and it does not,
because the chain links **`message_id`s** — and `message_id` is a hash of the
*original* content (§10). Blanking a row's stored content leaves its identity and
its position untouched, so the chain still verifies end to end.

So deletion is **tombstoning**: retain `message_id`, `seq`, `prev_hash`, and
sender; discard the content. The one cost is that a tombstoned entry can no
longer be re-derived from its content, so that single link becomes unverifiable
to anyone who did not keep a copy. The chain around it is unaffected.

This property falls out of content-addressing for free. It would have been
expensive to add later, and it is a good reason not to chain over stored rows.

#### What deletion actually guarantees

| Scope | Guarantee |
| --- | --- |
| The host's copy | **Removed.** Tombstoned, not recoverable from the server |
| Clients that are online and well-behaved | Removed on receipt of the delete event |
| Member exports and offline clients | **Not removed.** Nothing reaches them |

This is the same guarantee every messaging system actually provides — Signal,
Discord and Matrix all issue a delete request that honest clients honour, and
none can reach a copy someone already kept. The difference here is that Veil
*encourages* members to keep copies, so the gap is wider and more predictable.

**Say so in the UI.** "Deleted for everyone" is a lie in every product that
prints it; here it would be a larger one.

#### Erasure requests and account deletion

An erasure request reaches the host and no further. The operator can tombstone
every message a user sent and drop their account, and cannot touch the copies
members hold — for a Sealed community, cannot even read what it is being asked to
remove.

This is the same shape as §7.6's legal analysis: the blunt instruments exist and
work, targeted removal beyond the server does not. Operators should know that
before they run a public community, and it belongs in their published policy.

Account deletion has a further limit worth stating: a `UserId` is derived from a
key (§5.1) and past messages are signed by that user's device keys, so **the
authorship of existing messages cannot be unmade** — only their content
tombstoned and their account closed.

---

## 11. Abuse resistance

### 11.1 Why per-user rate limiting is not enough

The blind relay collapses every user behind one address by design, so per-IP
limiting at the community host is meaningless. The obvious fix is per-`UserId`
limiting — but **identity is free**. A `UserId` is a keypair; an attacker runs one
home server and mints ten thousand. Rate limits and bans both evaporate: ban an
ID, they generate another in milliseconds.

Sybil resistance, not rate limiting, is the actual problem, and it cannot be
solved at the network layer.

### 11.2 Home server attestations

Trust is therefore anchored one level up. A user presents a short-lived signed
attestation from their home server:

```
HomeServerAttestation {
  user_id:        UserId,
  home_server_id: [u8; 32],
  issued_at:      u64,
  expires_at:     u64,        // short, so lapsing is the revocation mechanism
  signature:      [u8; 64],
}
```

The attestation says only *this account is registered with me*. It deliberately
carries **no verification level** — see §11.2.1 for why that is checked directly
instead.

The home server stakes its reputation on the users it vouches for. Community
hosts throttle and block at home-server granularity.

**This does not compromise portability.** The attestation is swappable, the
`UserId` is not — move home servers, get a new attestation, keep your identity
and your verified relationships.

**It is not an identity mechanism.** A home server can refuse to vouch for a
user; it cannot forge who they are (§4.3).

### 11.2.1 Verification is direct, never delegated

**A server that requires verification performs it itself.** It does not accept
another server's word for it.

If a community host requires a phone check, the user verifies **with that host**
at join time. Their home server is not involved and is not asked to vouch for
anything beyond the account existing.

The alternative — home servers verify, community hosts trust the claim — was
considered and rejected. It makes lying free: a malicious operator writes
`Phone` in every attestation, checks nothing, and the field becomes decorative.
Patching that requires reputation tracking to catch liars, a standing model to
weigh claims against, and a lag window during which the fraud works. Direct
verification deletes all of it, because the party that cares does the checking.

#### The menu, and its honest costs

**A community declares what it requires; the protocol carries the requirement but
never fixes the list.** This must be an extensible descriptor with a registry of
method identifiers, *not* an enum — an enum means every new method costs a
protocol version bump (§3.6), and methods will change faster than the wire format
should.

| Method | Bulk cost to an attacker | PII collected | Self-hostable |
| --- | --- | --- | --- |
| Proof-of-work challenge | compute only; linear in accounts | none | yes |
| Interactive captcha | ~$1 per 1000, solved commercially | none | yes |
| Email OTP | ~zero — disposables are free, a domain gives unlimited addresses | weak | yes |
| Account age / activity | time | none | yes |
| Vouching by *n* members | needs real social access | none | yes |
| Phone OTP | ~$0.10–1.00 per number | **strong** | needs an SMS account |
| Refundable deposit | the deposit, per account | payment rails | needs a processor |
| External proof-of-personhood | high | varies, sometimes biometric | no |

**Default: proof-of-work plus email OTP.** Phone stays available and is never the
baseline, for two reasons — a phone number is a durable real-world identifier
where a throwaway address is not, and SMS costs money per check, so a phone
baseline would be affordable only to funded operators. That would quietly close
the door §1.3 exists to hold open.

Notes on the less obvious entries:

- **Proof-of-work is the best default addition.** It is invisible, collects
  nothing, and self-hosts — mCaptcha, ALTCHA and Friendly Captcha all work this
  way. It raises bulk-registration cost linearly rather than absolutely, so treat
  it as a speed bump, not a wall. Critically for §1.3, self-hostable PoW avoids
  the trap where the default anti-bot measure requires a commercial account with
  a third party.
- **Vouching is strong and underrated** — it needs genuine social access rather
  than money, and it composes naturally with invite-only (§11.3) rather than
  competing with it.
- **External proof-of-personhood** — World ID (biometric), BrightID (social
  graph), Gitcoin Passport (aggregated stamps), Idena (timed AI-hard puzzles) —
  offers the strongest sybil resistance available, and every one of them
  introduces a trusted external party, some with biometric databases. Support
  them as **pluggable, per-community, opt-in** methods. **Never protocol-required
  and never the default**, which would breach §1.3 outright.

Methods compose, and should: PoW blocks scripted bulk registration, email forces
per-account setup, account age denies instant throughput, and none is free at
volume once rate limits apply.

Blocking disposable-email domains is the obvious hardening, and it is a blocklist
with the same pluralism requirement as §11.4 — offer one, never require it, and a
host that subscribes to none must stay fully functional.

**This is a §1.3 win, not just a simplification.** Under delegation, a
self-hoster's attestations are worth less than a big server's until they build
standing — trust becomes something the small operator has to earn from strangers.
Under direct verification nobody's attestation is trusted for this, so a
self-hoster stands on exactly equal footing from day one. The verification
dimension stops being a centralisation gradient at all.

**The cost is a real privacy regression, and it is the user's to accept.** A
phone number is a strong real-world identifier, and this hands it to every host
that demands one rather than to a single server the user chose. Since `UserId` is
already stable across communities, the marginal *linkability* is small — but the
step from pseudonymous to real-world-identified is not, and it is taken with
strangers rather than with someone the user picked.

Three constraints follow, and they are not optional:

- **Store a salted hash, never the number.** Salt per community. That is
  sufficient to detect "this number already joined here" and nothing more.
- **Discard the number after verification.** It is needed for one SMS.
- **Require it only for public communities.** Invite-only communities have no
  sybil problem to solve (§11.3), so demanding a phone number there is pure
  collection with no security benefit.

Verification requirements are **per-community policy, never a protocol
requirement**. A user who verifies nothing is fully functional, joins any
community that does not demand more, and hosts their own without restriction.
Requiring a commercial verification account to participate *at all* would breach
§1.3.

Note the residual asymmetry: running SMS verification costs money per check, so
only reasonably funded hosts will require phone. That is fine — it makes the
requirement rare, which is the right outcome anyway.

### 11.3 Invite-only by default

Sybil attacks need open registration to a community. Most communities are
private, and for those the problem does not arise. Reserve the reputation
machinery for public communities, where it is genuinely needed.

### 11.4 Reputation without gatekeepers

Direct verification (§11.2.1) removes identity trust from this problem — no host
weighs another's word about who a user is. What remains is **relay-level abuse**:
because every user behind a home server shares its IP at the community host,
flooding and connection spam still need a granularity to act on, and the home
server is the only one available.

So reputation persists, but with a much smaller job: rate-limiting traffic, not
adjudicating identity. Scope it accordingly and resist letting it grow back into
a trust oracle.

**The structural risk is that reputation systems centralise.** Email is the
cautionary tale: self-hosting mail is now effectively impossible because
reputation gatekeeping makes new senders undeliverable by default. Matrix went
the same way more softly, with one homeserver holding a large share of users. If
community hosts distrust unknown home servers by default, everyone converges on a
few big ones and the decentralisation that motivated the architecture is gone.

The rule that avoids it: **trust must be earnable automatically, never granted by
an authority.**

- A new home server is **throttled, not blocked** — low join and message rates.
- Headroom grows with time and clean behaviour, tracked **locally by each
  community host**.
- **No central registry, no allowlist to petition.**

Slower to bootstrap, but nobody holds the gate. Shared blocklists may be
*offered* as an opt-in convenience; they must never be required to participate.

**Expect this to erode, and plan for it.** Automatic ramping stops casual spam
but not commercial spam, because aging a home server costs a few dollars a month
and patience, and spammers have both. When it fails, hosts fall back to manual
blocking, which becomes shared blocklists, which is a de facto authority — the
email outcome above.

The realistic goal is therefore not to prevent curation but to keep it
**pluralistic**: many competing lists, trivial to publish one, trivial to run
none. A host that subscribes to nothing must remain fully functional. One list
becoming universally required would breach §1.3.

### 11.5 Finding communities

No federation means no shared directory, and a public community nobody can find
is not much of a public community.

**A public showcase site, run alongside the app's own website.** Communities opt in to
being listed. This is a central index, and that is acceptable **only because it
is optional**: a community works identically whether or not it appears there,
listing is not a prerequisite for anything, and anyone may run a competing
directory. Nothing in the protocol references it.

Two costs to accept knowingly: running a public directory means taking on
moderation and the legal surface that comes with people listing things they
should not; and being the default directory is soft power, which is exactly why
delisting must never break a community.

### 11.6 Finding people

Three layers, and keeping them distinct is the whole design:

| Layer | Form | Property |
| --- | --- | --- |
| **Identity** | `UserId` (pubkey-derived, §5.1) | Self-certifying, portable, never changes |
| **Address** | `alice@veil.example` | Human-usable, server-controlled, **re-assignable** |
| **Sharing** | link or QR carrying the full `UserId` | No lookup, so nothing to substitute |

#### Sharing carries the whole key

Addresses are shared as links or QR codes, and those carry the **full `UserId`**,
not a name to look up. That removes the substitution attack entirely rather than
mitigating it: there is no directory answer to falsify, because no directory is
consulted.

This matters because **anything a server tells you, that server can lie about** —
including a profile, since the profile is served by the same machine. If Bob
resolves `alice@veil.example` and the server is compromised, it can hand him an
attacker's key and transparently sit in the middle. A link that already contains
Alice's key has no such step.

Name resolution therefore exists only for the case where somebody types an
address by hand. It is trust-on-first-use, and safety numbers (§6.1) remain the
real verification, exactly as Signal handles phone numbers. **No fingerprint or
checksum in the address** — with links and QR as the normal path, it would add
UI surface to protect a case that barely occurs.

#### The alias is never the identity

Clients pin the `UserId`, never the alias, and **warn loudly if an alias later
resolves to a different `UserId`** than the pinned one — the same mechanic as
server-identity pinning (§6.2).

This is what keeps §5.1's portability real rather than nominal. Aliases are
server-controlled and re-assignable: an operator can hand `alice@` to somebody
else after Alice leaves. If users experienced the alias *as* the identity, moving
servers would mean becoming a stranger, and Matrix's `@user:server` welding would
return through the interface even though the protocol does not have it. Alice
changes hosts, her alias updates, and every contact and verification survives
because they were pinned to her key.

#### Mailbox servers are an ordered fallback list

A user publishes an **SSK-signed, ordered list** of servers that accept mail for
them (§5.4), so no server can lie about where their mail goes. Senders try them
in order — this is MX records, and the model has worked since 1986.

- **Send to one.** The rest exist for when it is unreachable, not for fan-out.
  Only the server that actually receives learns anything, so metadata exposure
  stays at one server in the normal case.
- **A backup forwards to the primary once it recovers**, otherwise mail strands
  wherever it happened to land. This needs no new mechanism: the backup simply
  acts as a sender toward the primary, reusing §3.3's delivery path.
- **Clients poll every listed server anyway**, as a safety net for mail not yet
  forwarded. Deduplication is free because `message_id` is content-addressed.
- **Cap the list** — around five. Not for amplification reasons, since delivery
  is sequential, but so a sender does not burn thirty timeouts walking a long
  list during a failover.

---

## 12. Persistence, delivery, and durability

Unbuilt. Today all state is in memory and offline messages are dropped.

### 12.1 Stores

- **Key directory** — users, devices, cross-signatures, prekey bundles.
- **Mailbox** (home server) — per-device queues for DMs (§3.4) and notifications.
- **Message store** (community host) — per-channel append-only log keyed by
  `(channel_id, seq)`. Sealed rows hold ciphertext; Open rows hold content
  encrypted at rest. **Not built**: channels have no transport yet, and a store
  for traffic that cannot arrive would be guesswork.

**SQLite by default, Postgres as the scale path.** §12.1 originally named
Postgres for all three, but requiring a database server to run a home server is
friction §1.3 cannot afford — the invariant is that one person on a domestic
connection can run one. The schema is deliberately plain so moving a large host
to Postgres is a port rather than a redesign.

### 12.2 Delivery

Two paths, because channels and DMs are ordered differently (§10).

**Community channels — cursor-based.** A device reconnects, reports its last-seen
`seq` per channel, and receives everything after it. One authoritative host means
one total order, so this subsumes live delivery and history sync into a single
code path.

**DMs — acknowledge and retain.** There is no `seq` to resume from: a
conversation's messages live in two different mailboxes and no server sees both
sides. A mailbox is an unordered set, so delivery is by acknowledgement — an
entry is retained until *every* one of the recipient's devices has acked it, then
dropped. Clients order what they receive themselves, from Olm's per-session
message indices plus `seen_head`.

This is also what makes fallback mailboxes (§11.6) safe: with nothing to
sequence, several mailboxes need no consistency between them, and duplicates
collapse on the content-addressed `message_id`.

#### Push notifications

Follow Signal: **the push itself carries nothing.** The home server sends a
contentless wake-up through APNs or FCM; the device wakes, connects to its own
home server, fetches the message, decrypts locally, and builds the notification
itself. Apple and Google therefore see *that* a device had something waiting and
when — never content, never sender.

Two separate settings, easily conflated:

- **Contentless push** is architectural and not optional. It is what keeps the
  platform push services out of the content path.
- **Lock-screen preview** — whether the decrypted text appears on a locked
  screen — is a client display preference. Default on, since that is what people
  expect, and it never affects what APNs or FCM sees.

**Polling mode.** Offer an option to skip push entirely and check on an interval
(hourly by default). It costs latency and battery, and it buys resistance to
timing correlation: nobody learns when each individual message arrived, only that
the device checked in on a schedule. It also doubles as the escape hatch below.

> **Polling is built; contentless push is not.** Push needs APNs and FCM
> credentials, a signed application, and a device to receive on — none of which
> exist yet, and none of which can be exercised from a desktop. Polling is the
> half that works today, and it is deliberately the half that matters for §1.3:
> it is what stops the push gateway becoming a dependency.

#### Push is a §1.3 exception, and should be named as one

Push tokens are bound to a signed application, so APNs and FCM credentials belong
to whoever ships the app. A self-hosted home server therefore **cannot push to
the official client directly** — it must route through a project-run push gateway,
exactly as Matrix homeservers route through a gateway for Element.

This is a genuine central dependency and the fourth consolidation force after the
three in §1.3. What keeps it tolerable:

- the push is contentless, so the gateway learns only *device X has something
  waiting* — no sender, no content, no community
- **polling mode removes the dependency entirely** for anyone who objects, which
  is what preserves the §1.3 invariant
- a self-hoster shipping their own app build runs their own gateway and is fully
  independent

Do not let the gateway grow beyond wake-up signalling. The moment it carries
anything else, it becomes infrastructure the network depends on.

### 12.3 Backups

Distribution is the whole problem. A backup nobody can restore is not a backup,
so the target is a **one-command restore**: download the archive, drop the path
into a supplied `docker compose` file, start it. Friction here is what decides
whether recovery ever actually happens.

Who may hold a backup differs by tier, because the tiers differ in what a backup
*is*.

> **The server-side half is built; the community-level half is not.** A store
> can be backed up consistently, verified, and restored — `VACUUM INTO` rather
> than copying a live WAL file, since a torn copy is the kind of backup that
> looks fine until the day it is needed. What is *not* built is the filtered
> per-member export below, because it filters on channel readership and channels
> have no transport yet.

**Sealed — any member, on request.** The database is ciphertext. Handing a
complete copy to a member leaks nothing they could not already read; in fact it
leaks *less*, since they hold Megolm keys only for the eras they were present
for. This is what makes Sealed communities durable (§7.1): the host is an
untrusted blob store, and every member can hold a full replica.

**Open — a filtered export per member, plus a controller-encrypted full backup.**
The database is plaintext, so an *unrestricted* download would be an ACL bypass
wearing a backup hat: it would hand every member the full history of channels
they cannot read, private admin channels, moderation logs, and any mailboxed DMs.

The fix is to filter rather than to withhold. **Any member may download a backup
containing exactly what their permissions already let them read** — their
channels, and nothing else. Admin channels, moderation logs, and other members'
DMs are never in anyone's export. This leaks nothing, because it contains only
what that member could already page through in the client.

Two mechanisms, and they cover different things:

| Backup | Who holds it | Covers |
| --- | --- | --- |
| **Filtered export** | any member, on request | everything at least one member can read — the bulk of history |
| **Full backup** | encrypted to controllers, k-of-n | the above plus admin channels and moderation logs |

Filtered exports make Open communities durable in the same way Sealed ones are:
**every member becomes a partial replica**, and the union of members' exports
reconstructs essentially the whole community. Merging is straightforward because
`message_id` is content-addressed (§10) and the hash chain (§10.1) makes each
fragment verifiable rather than merely asserted.

What remains exposed is much narrower than before: if a threshold of controllers
is lost, **admin-only content** is unrecoverable. Ordinary history is not. Losing
moderation logs is survivable in a way losing the community was not.

**Both tiers: the archive excludes the host's own private keys.** A restored
instance generates a fresh host identity on first boot. Otherwise anyone holding
a backup could impersonate the original host, and clients pin host identity keys
**[built]**, so a restore is visibly a different host by construction.

**Metadata in a Sealed archive is accepted, deliberately.** The dump carries the
member list, join dates, message timing and volume, and device lists. Members can
already observe essentially all of this by being present, so the marginal
exposure — mostly activity patterns of quiet members and of people who have since
left — is judged acceptable in exchange for the durability.

A Sealed archive is only half of history, though: the ciphertext is replicable,
but the Megolm keys that make it readable live on member devices. Those are
covered separately in §12.5.

### 12.4 Succession

A backup gives you the *data*. It does not tell clients *which host is now the
community* — every restored copy shares the same `CommunityId`. Availability and
identity are separate problems and need separate mechanisms.

**Signed migration — the legitimate path.** A threshold of controllers signs a
record redirecting clients. `CommunityId` is unchanged, the community continues,
and clients follow automatically:

```
CommunityMigration {
  community_id: CommunityId,
  new_host:     String,
  sequence:     u64,            // monotonic; blocks replay of a stale record
  signatures:   Vec<[u8; 64]>,  // >= threshold, from distinct controllers
}
```

Clients accept only the highest `sequence` seen, so a stale record cannot
redirect a community to a dead or hostile host. Because controllers are k-of-n
(§7.4), this survives the operator vanishing as long as a threshold of admins
remains.

**Unsigned fork — the last resort.** If every controller is gone, anyone holding
a backup can still stand the community up. Such a copy does **not** inherit the
original `CommunityId`. It re-roots as a new community carrying a signed
`successor_to` pointer at the old one, and members opt in explicitly.

This is the important asymmetry: a fork presents honestly as a successor rather
than claiming to *be* the original, which removes the impersonation surface
entirely. If forks could claim the original ID, the backup feature would double
as a community-hijacking primitive.

Practically this means **a Sealed community cannot be killed by its operator**.
Worst case it re-roots under new management and members follow by choice.

Forks are also expected to appear at a different address, since a restore has
neither the original host's keys nor its DNS. Clients should surface a fork as
what it is rather than papering over the discontinuity.

#### k-of-n is a per-community policy, not a constant

Do not hardcode the threshold. Every setting trades durability against
confidentiality, and different communities sit at different points:

- **Raise `n`** — more people can restore, but more people can read admin
  channels, moderation logs, and private history in an Open backup.
- **Lower `k`** — recovery gets easier, and so does a hostile takeover by a
  minority of admins.

A hobby community would rather survive than keep admin channels secret. One
handling sensitive material would rather die than leak. The founder picks the
point on the curve; the UI explains which way the dial cuts.

Note the asymmetry that falls out of §12.3: this dial only governs **Open**
communities. Sealed backups are member-restorable, so Sealed durability does not
depend on the controller set surviving at all.

#### Controller liveness

**Communities die of drift, not catastrophe.** The realistic failure is not "the
admin died" — it is three admins who quietly stopped logging in over two years,
noticed only when the host lapses.

So track controller liveness and nudge: *"only 1 of your 3 controllers has been
seen in 6 months — add more?"* This costs no cryptographic concession and catches
the majority of real-world losses, which are ordinary attrition. It is worth more
in practice than any refinement to the recovery mechanism itself.

### 12.5 Client-side key backup

Sealed history depends on member key material, and the server must never hold
Megolm keys in usable form — it could otherwise read everything, which is the
whole point of the tier. Two mechanisms, in order of how often they are used.

**Cross-device sharing — the common path.** A user's existing device hands
session keys to a newly added one, authenticated over cross-signing (§5.4).
Anyone with two devices never touches recovery at all. This covers nearly every
real case.

**Encrypted key blob — for losing every device at once.** The client encrypts its
keys locally and gives the server the *ciphertext*. The server stores an opaque
blob it cannot read — the same logic as §12.3, applied to keys rather than
messages. This is what Signal (Secure Value Recovery) and Matrix (server-side key
backup) both do.

**The blob's key must be randomly generated, not a passphrase.** A user-chosen
passphrase lets a malicious server brute-force the blob offline at its leisure,
which turns the whole mechanism into theatre. Generate a high-entropy recovery
key and have the user store it. The UX cost is one string kept somewhere safe, for
something touched once — acceptable, and Matrix demonstrates it is workable.

#### One recovery key covers identity as well as history

The blob holds **MSK, SSK, USK, and the Megolm backup key** — Matrix's SSSS
model. This deliberately collapses what were three separate problems (account
recovery, master-key custody, message-key backup) into one secret, because
splitting them just gives the user more things to lose.

Consequences, accepted:

- **A password alone never restores anything.** It authenticates you to a server;
  it does not decrypt the blob and does not grant history.
- **No recovery key and every device lost means the identity is gone.** The MSK
  is unrecoverable, so the `UserId` is unrecoverable (§5.1), and the user returns
  as a new person whom contacts must verify afresh. This is harsher than Signal,
  where re-registering a phone number preserves the identity even when history is
  lost. It is accepted: the alternative is server-held escrow, which reintroduces
  exactly the trust the model removes.
- The client should therefore push recovery-key setup **at enrolment**, not bury
  it in settings, since that is the only moment the user still has the option.

#### New devices are verified by an existing device, then receive full history

A new login is **not** authorised by the account password. An already-verified
device must approve it interactively, exactly as Matrix does, and only then are
keys handed over (§5.4). On approval the new device receives **all** history the
approving device holds.

This is what stops a server that has compromised or coerced a password from
silently adding a device and reading everything. The password gets you an
account; another device gets you the keys.

Be precise about what the approval gate does and does not cover:

- **Covered:** remote compromise — stolen credentials, a malicious or coerced
  server. None of it yields history without physical approval on a device the
  user already holds.
- **Not covered:** physical compromise. Someone holding an unlocked device
  already has that device's history, and can approve themselves onto another.
  Full handover means one compromised device exposes everything it held. This is
  the accepted cost of the convenience, and it is what Matrix users get today.

#### Transfer keys as one bundle, not one message per session

Matrix's first attempt at this (MSC3061) sent a to-device message *per megolm
session per recipient device*, and the spec's own successor describes that as
**"prohibitive"** — a room accumulates sessions forever, so the cost grows without
bound. MSC4268 replaced it: bundle every eligible key into a **single encrypted
file**, upload once, and send one to-device message pointing at it.

Build the bundle version. The naive per-session loop is the obvious
implementation and it is the one Matrix had to abandon.

#### Historical keys need stricter rules than new keys

MSC3061's implementation in `matrix-js-sdk` carried a security vulnerability
(disclosed October 2024, versions 9.11.0–34.7.x) with a root cause worth copying
into our own test suite: it **applied the same sharing rules to existing keys as
to new ones**, so historical keys could be sent to unverified devices and users.

The two paths are not the same and must not share code:

| Path | Recipients |
| --- | --- |
| New session key for a channel | every current member device, verified or not |
| **Historical** keys | **only devices verified as our own** (§5.4) |

Sessions should additionally carry a `shared_history` flag, as MSC4268 does, so
that keys from periods a user was not entitled to read are never eligible for
handover in the first place.

---

## 13. Server architecture and scaling

### 13.1 Target shape

> **Not built, deliberately.** This is horizontal scaling for load that does not
> exist, and it cannot be validated without that load. Building a gateway split
> and a pub/sub bus now would be guesswork dressed as progress — the same
> reasoning that kept the community message store unbuilt until channels have a
> transport. The routing path was reshaped to make it *possible* (§13.3: the
> outbox change removed the socket-bound global lock that would have blocked it),
> which is the part that was cheap to do early.


```
clients ──► gateway nodes (stateless, hold WebSockets and relay tunnels)
                  │
                  ├──► pub/sub bus (Redis or NATS) ──► fan-out between gateways
                  ├──► key directory (Postgres)
                  └──► message store / mailbox (Postgres)
```

Gateways hold no authoritative state, so they scale horizontally and a node
failure costs only reconnections.

### 13.2 One logical server, many machines

A home server or community host presenting as one logical server while running
across several machines is the §13.1 shape — stateless gateways over shared
stores. Worth being precise about what it solves:

- **Multi-machine hosting** solves *a box died*. Availability within one operator.
- **Backups** (§12.3) solve *the data must survive the host*.
- **Succession** (§12.4) solves *who is the community now*.

Three different problems. Multi-machine hosting does nothing if the operator
disappears, and a backup does not tell clients where to reconnect — each needs
its own mechanism.

### 13.3 Known blockers in the current implementation

Verified issues in today's code. None have protocol implications — all are Tier 2
(§15).

- ~~Routing lock held across an await~~ — **fixed.** `CLIENTS` now maps to
  bounded per-connection outboxes drained by their own task, so routing never
  waits on a socket. A peer that fills its outbox is disconnected rather than
  blocking everyone behind it or having messages silently dropped.
- **Keyring write per message** — the client serialises its entire state to JSON
  and writes it to the OS keyring after every message, twice per send.
- ~~`ReplayGuard` prunes O(n) per check~~ — **fixed.** Sweeps periodically
  rather than per message. Sweeping late cannot reopen the replay window: the
  timestamp check rejects old messages regardless of what is remembered.
- ~~`RateLimiter` never evicts idle keys~~ — **fixed.** Windows that have fully
  elapsed carry no information and are swept.
- **`CLIENTS` is a process-global** — blocks horizontal scaling by construction.
- **`/clients` enumerates every connected user** — rate-limited, but the real fix
  is per-user contact lists rather than a global roster.
- **Unauthenticated prekey fetches** — rate limiting bounds the damage; closing it
  properly needs authenticated HTTP.

### 13.4 Time synchronisation

`ReplayGuard` accepts a ±60s window against wall-clock time (**[built]**), and
`server_ts` orders history (§10). A self-hosted box with a drifting clock
therefore fails to talk to anyone, and surfaces as a signature rejection — close
to undiagnosable for the operator.

**The server queries SNTP itself and keeps an internal offset.** It does not set
the system clock: a container shares the host's clock and cannot adjust it
without `CAP_SYS_TIME`, which would alter the host. Reading the time is a plain
outbound UDP request that works anywhere, so the server computes
`offset = ntp_time - system_time` at startup and periodically, and applies it to
every protocol timestamp. Roughly fifty lines, no privileges, no host
configuration, and it works identically in Docker and on bare metal.

Three requirements:

- **Query several independent sources and take the median.** NTP is
  unauthenticated by default, so an on-path attacker who controls the answer can
  widen the replay window — clock skew is a *security* control here, not just an
  operational nicety. NTS (RFC 8915) is the stronger option where available.
- **Degrade loudly, not silently.** If no source is reachable — air-gapped or
  firewalled — fall back to the system clock and warn, rather than refusing to
  start.
- **Report skew as skew.** When the replay guard rejects for timestamp drift, say
  *"peer clock differs by N seconds"* rather than failing as a bad signature. This
  is the difference between a one-line fix and an unanswerable bug report.

**Built server-side only.** The client still stamps from its own system clock,
which is usually fine — desktops run NTP — but a client in a container has the
same exposure as a server in one. The skew message names both ends for that
reason.

---

## 14. Metadata

Stated as a property rather than left as an accident.

| Observer | Sees |
| --- | --- |
| Your home server | which hosts you talk to, who you DM, volume, timing, your IP |
| Community host | your UserId, your participation, your home server |
| A peer's home server | that your server sent them a DM, and when — never your IP |
| Network attacker | nothing beyond TLS-visible endpoints |

The blind relay splits the metadata rather than eliminating it: the home server
knows *who you are* but not *what you said*; the community host knows *what you
said* (Open) but not *where you are*. Neither has the full picture, which is a
real improvement over a centralised service — but it is not anonymity and must
not be described as such.

#### Content is never readable by a home server, in either tier

Worth separating from everything else here, because it is the strongest property
in the system and the easiest to state loosely:

- **Sealed** — content is E2EE, so no server decrypts it, ever.
- **Open** — the community host reads content by design, but the *home server*
  still cannot: the client's TLS session with the host runs nested inside the
  relay tunnel (§3.2).

So a home server never reads message content regardless of tier. That is
absolute, and it is what "your own server cannot spy on you" actually means.

#### But encryption protects content, not routing

The same home server plays two different roles, with different exposure, and
conflating them is the easiest mistake to make here:

| Traffic | Home server's role | What it necessarily learns |
| --- | --- | --- |
| Community | **blind relay** | that you connected to host H, volume, timing — not which channels, not who you spoke to |
| DM | **active router** | sender, recipient, timing — it cannot deliver without a destination |

The DM row is structural, not an implementation shortcut. Store-and-forward
(§3.4) requires the forwarding server to know where it is forwarding to. No
amount of content encryption changes that, because the destination is not part of
the content.

**Sealed sender** would close half of it — encrypting the sender's identity inside
the payload so the *recipient's* server sees only who a message is for. It cannot
close the other half: your own server authenticated you, so it knows you sent
something and where it went.

Reducing this further (sealed sender, padding, cover traffic) is out of scope and
should not be claimed as a property Veil already has.

**Retain as little of this as function allows.** Content encryption does not
protect metadata, and disclosure orders reach whatever a server holds (§7.6). A
home server needs recent routing state to deliver mail; it does not need an
indefinite log of who messaged whom. Default retention windows should be short,
operator-configurable, and documented — minimisation is the only defence that
works against an order you cannot refuse.

---

## 15. Sequencing

**Tier 1 — foundations. Retrofitting these is brutal; do them first.**

1. User/device separation, self-certifying `UserId`, device lists (§5.1–5.3)
2. Cross-signing and the verification chain (§5.4)
3. Message IDs, host-assigned ordering, and the hash chain (§10, §10.1)
4. Community roots, k-of-n controllers, tier binding, policy chain (§7.4) —
   including channel read-membership, which senders rely on for key distribution
   (§8.5)
5. `GroupKeyProvider` boundary, Megolm behind it (§8.4)
6. Blind relay transport, tunnel protocol, and destination handshake
   verification (§3.2) — the anti-open-proxy check ships *with* the relay, not
   after it
7. Version negotiation, signed into the handshake transcript (§3.6) — must land
   before the first release, since v1 clients need something to negotiate *with*

**Tier 2 — mechanical. No protocol implications.**

8. Persistence: key directory, mailbox, message store (§12.1)
9. Offline queue, fallback mailboxes, reconnect-driven delivery (§12.2, §11.6)
10. The blockers in §13.3, starting with the routing lock
11. SNTP offset and skew reporting (§13.4)
12. Gateway/pub-sub split for horizontal scale (§13.1)
13. Attestations and per-host reputation (§11.2, §11.4)
14. Member-restorable backups and the one-command restore path (§12.3)
15. Device enrolment and key handover (§12.5) — **as a single bundled file, and
    with historical-key rules separate from new-key rules**; both are there to
    avoid a defect Matrix shipped
16. Encrypted key blob and recovery key (§12.5)
17. Contentless push and polling mode (§12.2)

**Tier 3 — features.** Communities, channels, roles, bots — plus the designed
subsystems that hang off them: attachments (§10.2), presence and typing (§10.3),
search (§10.4), moderation tooling (§7.6), and directories (§11.5–11.6).

Two carry more weight than their position suggests:

- **Calls (§9)** are Tier 3 in ordering but Tier 1 in design cost — a separate
  crypto path with its own MLS requirement, not a feature riding on messaging.
- **Roles (§8.5)** are Tier 3 as a feature, but their *signed read-membership
  state* is Tier 1 item 4, because senders rely on it to decide key distribution.

### 15.1 Unverified numbers

Two figures here are **engineering estimates, not measurements**, and are accepted
as low risk on the basis that comparable systems already work: Element runs
encrypted rooms and encrypted video calls in production at these scales.

- **§7.1's "few hundred members"** Sealed ceiling — governed by Megolm rotation
  cost at roughly Σ(devices per member) per rotation.
- **§1.3's "a few dozen friends"** relay invariant — governed by concurrent
  relayed video and screenshare, with selective forwarding, simulcast, and the
  P2P escalation (§9.1) all bounding it.

Neither blocks Tier 1. Worth a sanity check whenever load-testing is convenient,
mainly so the numbers in this document can stop being estimates — but they should
not gate the build.

One caveat on the comparison, so it is not leaned on too hard: Element's success
with encrypted calls demonstrates that **the cryptography** is not the
bottleneck. It says nothing about a **domestic uplink**, since Element Call
deployments run on real server bandwidth. If self-hosters ever report poor call
quality, uplink saturation is the first thing to check, not the crypto.

---

## 16. Open questions

- **Admin-only content in Open still depends on the controller set.** Filtered
  per-member exports (§12.3) removed the serious version of this — ordinary
  history now survives on members' copies regardless of what happens to the
  admins. What is still lost if a threshold of controllers goes is **admin
  channels and moderation logs**, which nobody else is entitled to hold. Accepted:
  every alternative is worse, since widening who can decrypt them is precisely
  the ACL bypass filtering was introduced to avoid.
- **Relay capacity on a domestic uplink is an estimate.** *Accepted as low risk.*
  Text and signalling are negligible; the whole constraint is concurrent relayed
  video and screenshare (§9.1) at 1–8 Mbps per stream, bounded by selective
  forwarding, simulcast, and the P2P escalation. Element runs encrypted calls in
  production, so the cryptography is not the bottleneck — but that says nothing
  about home bandwidth, so uplink saturation is the first suspect if self-hosters
  report poor call quality (§15.1).
- **The Sealed membership ceiling is an estimate.** *Accepted as low risk.*
  §7.1's "few hundred members" is not measured, and no public benchmarks for large
  encrypted Matrix rooms could be found — but Element runs encrypted rooms at
  these scales in production. The binding cost is churn × devices (§8.3), and
  large communities default to Open anyway, which keeps Megolm off the critical
  path (§15.1).
- **Sybil resistance is a per-community policy choice, and its floor is low.**
  *Resolved by §11.2.1's method menu.* Direct verification means a community
  checks each user itself, so home server standing only buys relay throughput
  (§11.4). Each community picks what it demands, and the honest floor for the
  cheapest options — proof-of-work plus email — is roughly the cost of bulk
  addresses plus compute. Communities needing more escalate up the menu;
  invite-only (§11.3) sidesteps it entirely. **No mechanism here proves distinct
  humans**, and verification proves only that someone completed a challenge.
- **Phone verification exposes a real-world identifier, and there is no clean
  alternative.** *Researched; accepted.* A mechanism proving possession of a
  distinct number without revealing it would need either a trusted issuer (blind
  signatures, anonymous credentials) or trusted hardware (Signal's enclave-based
  contact discovery). Both breach §1.3, which is why phone is never the default
  and never protocol-required. The §11.2.1 mitigations — salted hash per
  community, discard after the OTP, public communities only — remain **policy,
  not enforcement**: nothing stops a host retaining the number.
- **Deletion cannot reach member-held copies.** *Accepted; the cost of choosing
  durability.* §10.5 covers what is and is not guaranteed. Flagged here because it
  is the one place where a headline property of the design (communities outlive
  their operators) directly removes a capability users will expect.

---

## 17. Client architecture

Everything above is protocol. This section is the client, and it is **partly
decided**: the seam is settled, the toolkit within Qt is not.

### 17.1 The seam is the load-bearing decision

```
veil-protocol/      wire types, envelope, crypto primitives        [exists]
veil-client-core/   sessions, key management, storage, Tantivy     [to build]
                    index, network, message pipeline — NO UI
veil-gui/           Qt bridge + UI                                 [to build]
veil-server/                                                       [exists]
```

**`veil-client-core` must never know a UI exists.** That single rule buys three
things: the CLI keeps working, mobile (§17.4) reuses it wholesale, and if the
desktop toolkit turns out wrong in two years only `veil-gui` is rewritten.

Everything security-sensitive lives in the core — Olm/Megolm state, the keyring,
key backup, the search index — and never crosses into UI code. Today's client
mixes these: `state.rs`, `messaging.rs` and `listener.rs` all interleave protocol
work with `println!`. Untangling that is a precondition for any GUI.

**Threading.** The core owns a tokio runtime on its own threads. Signals marshal
to the Qt UI thread via queued connections. The UI thread never touches crypto and
never blocks on I/O.

### 17.2 Desktop: Qt, and explicitly not a webview

Webview shells (Tauri, Electron) are **ruled out** — WebKitGTK on Linux is
unreliable enough to disqualify the approach, and a chat client cannot afford a
flaky renderer on a tier-one platform.

Qt earns it on the merits that matter here:

- **Text.** HarfBuzz and `QTextLayout` give correct IME, RTL, complex emoji, and
  selection. This is where immature toolkits fail hardest and a chat client
  cannot compromise.
- **Docking.** `QDockWidget` has shipped draggable, floatable, persistable panels
  for two decades (`saveState()` / `restoreState()`); KDDockWidgets extends it.
  Panel rearrangement is a *native strength*, not something web does better.
- **Maturity.** Twenty-five years of desktop deployment.

Ruled out and why: **egui / iced** — `egui_dock` gives cheap docking, but
immediate-mode text handling is weak exactly where this app cannot afford it
(CJK input, emoji, RTL, accessibility, cross-message selection).

### 17.3 Decided: split process, Widgets shell, QML islands

| | Widgets (C++) | QML (cxx-qt) |
| --- | --- | --- |
| Docking | `QDockWidget`, built in | build it, or glue KDDockWidgets |
| Rich text | `QTextDocument`, markdown-capable | more manual |
| Message list, animation | fiddly | strong |
| Discord-like styling | fights native look | natural |
| Rust bridge | **cxx** — very mature | **cxx-qt** — maintained, smaller |

**Decided: Rust backend, C++/Qt frontend, and the boundary is a socket rather
than a linker.** Both options were built and both worked; the split was chosen.

```
veil-client-core   Rust library — sessions, keys, storage, Tantivy, network
veil-daemon        thin Rust binary wrapping it, local socket    <- desktop
veil-gui           C++/Qt — Widgets shell + QML islands          <- no Rust
```

The UI is a **Widgets shell** carrying the `QDockWidget` skeleton, with
`QQuickWidget` islands hosting QML for the message view and anything needing
custom styling. That takes docking for free *and* QML rendering where it matters.

#### Why a socket and not FFI

A linked build via `cxx` was spiked first and worked cleanly — both directions,
threading included, about thirty lines of bridge. It is not fragile. The split
was still preferred:

| | Linked (`cxx`) | Split (socket) |
| --- | --- | --- |
| Build coupling | cargo invoked from cmake | **none — independent builds** |
| Crash isolation | GUI fault takes the keys with it | **key material in its own address space** |
| Debugging | across an FFI boundary | **read the socket** |
| Other clients | must link the core | **CLI and third parties speak the same protocol** |
| Binary | ~3.9 MB GUI | ~124 KB GUI |

The isolation is the real argument, not the ergonomics: the GUI parses untrusted
images, embeds and link previews, and in the split model it does so in a process
holding no key material. This is the LSP shape — structured messages over a pipe,
each side free to be written in whatever suits it.

#### Validated by spike

`spike/qt-ipc/` is a working reference — `./run.sh`. Every load-bearing claim was
exercised: independent builds with no cargo in `CMakeLists.txt`; a real
`vodozemac` account in the daemon whose identity reaches the status bar;
request/response *and* daemon-initiated push; QML → C++ → socket → Rust;
`QDockWidget` panels persisting across a restart; and the daemon surviving a
`SIGKILL` of the GUI while continuing to serve.

Two things it deliberately does not settle, both wanted before real traffic:
**length-prefixed framing** in place of newline-delimited JSON, since messages
will carry binary; and authentication, reconnect, and backpressure on the socket.

### 17.4 Mobile: shared core, native UI

Qt runs on iOS and Android, and mobile is the weakest part of Qt's story:

- **Licensing.** LGPL requires dynamic linking or relinkable objects, and whether
  that satisfies App Store distribution has been a gray area for years. Many
  shops buy a commercial licence to stop thinking about it. AGPL-3 on our own
  code is not the friction — store distribution is.
- **Feel.** Qt Quick Controls approximate platform look rather than being it.
- **Integration.** Push via APNs/FCM (§12.2), background fetch, iOS Keychain and
  Android Keystore, share sheets, biometrics — all platform-specific glue that
  Qt does not save you. Qt does not remove the hard part of mobile.

**So mobile is native UI over the shared core** — SwiftUI and Compose on
`veil-client-core`, which is what Signal does with libsignal. Deferred entirely;
§17.1 is what keeps the option open at no present cost.

### 17.5 Panel layout, staged

Rearrangeable panels are a **nice-to-have and must not gate the message
pipeline**. Note that "move the friends list" is panel *rearrangement*, not
IDE-style floating windows — a much smaller problem.

| Stage | What | Cost |
| --- | --- | --- |
| v1 | Fixed layout | none |
| v2 | Rearrangeable panels, persisted | `QDockWidget`, or QML `SplitView` |
| v3 | Floating windows, tab groups | KDDockWidgets |

---

## 18. Bots

**A bot is an ordinary account.** It has a `UserId` derived from a master key,
devices, cross-signing, and a place in the member list. Every rule that applies
to a person applies to it unchanged: it holds a role, it can be banned, it is
subject to the channel set, and it appears in the reader list or does not.

That is a decision, not an omission. The alternative — a distinct principal type
with its own rules — would mean every check in the system growing a second case,
and the second case is where the bugs live. Matrix reached the same conclusion,
and it is why nothing in `veil-protocol` branches on whether a member is
automated.

### 18.1 What a bot can read in a Sealed community

This is the only question about bots that is a security decision rather than an
interface one, and the existing design already answers it.

In Sealed, read access **is** key possession (§8.5). A bot reads a channel if and
only if a signed `ChannelReaders` record names it, and senders consult that
record when deciding who receives Megolm keys. So:

- A bot with read access is **visible in signed policy**. Anyone can see it is
  there, and only controllers can put it there.
- A bot without it receives no keys, and no sender encrypts to it. It can still
  be a member, be mentioned, and post — it simply cannot read.
- A host cannot add one. The reader list is signed, which is the whole reason
  §8.5 put it in the chain rather than leaving it to the host.

**So "is a bot reading this?" is already answered by "who is in the reader
list?"** — and that list was made trustworthy for exactly this class of reason.
No new mechanism is needed, and adding one would create a second answer to a
question that already has one.

Worth stating plainly for the interface: **a bot in a Sealed channel reads
everything in that channel.** There is no partial key, and a design that promised
one would be lying — Megolm keys decrypt a session, not a subset of it. A
community wanting a bot that reads less should give it its own channel.

### 18.2 The automated marker

`PolicyRecord::Automated` marks a member as a bot. It is signed like any other
policy, so a host can neither invent one nor conceal one.

**It is a label and nothing else.** Nothing enforces it and nothing depends on
it, because a bot that lied about being one would still be bound by every rule
above. It exists so a member list can say which participants are automated,
which is honesty in the interface rather than a security control. Treating it as
the latter would be a mistake — the security comes from the reader list and the
role, both of which are already signed.

### 18.3 What a bot needs that a person does not

Nothing, at the protocol level, which is the point. Operationally it wants:

- **An unattended identity.** The recovery key (§12.5) is the mechanism; a bot
  keeps its cross-signing secrets in whatever the operator uses for secrets.
- **A stable alias** (§11.6), so people can address it by name. Server-controlled
  and re-assignable like any other, and clients pin the identity behind it.
- **Not to be a moderator by default.** A bot that can ban is a bot whose
  compromise can empty a community, and the role system already makes that an
  explicit grant rather than a default.
