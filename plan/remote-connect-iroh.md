# Transport for Remote Device Connectivity: Recommending iroh

- Status: evaluation draft
- Date: 2026-11-14
- Language: English. Keep this document, and every future document in `plan/` and `docs/`, in English.
- Scope: the "cloud interconnect" capability of gono-cloud. The first consumer is remote access in
  Input Show (keyboard and mouse, clipboard and screen viewing across the internet), followed by
  port forwarding and other products.
- Note: versions, APIs and figures for iroh come from its official documentation and blog as of
  November 2026. Anything marked "to be verified" must be confirmed by the checks in section 7.

---

## 0. Summary

**Recommendation**: use iroh (currently 1.4.1) as the connection layer between devices. It handles
QUIC, NAT traversal, multipath switching and relay fallback. gono-cloud handles accounts, the device
directory, authorization, address lookup, a self-hosted relay and auditing.

**Preconditions**: the following three checks must pass; otherwise we do not switch:

1. iroh builds and runs on HarmonyOS (`aarch64-unknown-linux-ohos`) (V1).
2. On a LAN, Input Show's pointer latency and CPU usage are no worse than with the current quinn
   implementation (V2).
3. iroh can run without contacting any server of n0, the company behind it (public relays, public
   DNS discovery) (V4).

**Principles that hold whichever transport we choose**:

- The cloud only helps devices find and reach each other; it is never a source of trust. Trust
  between devices still comes from pairing.
- Input Show's LAN mode and its use without an account stay as they are. Remote access is opt-in.
- Relays only forward ciphertext.

---

## 1. Background

### 1.1 What gono-cloud is for

gono-cloud is more than a WebDAV file server: it is meant to **provide cloud interconnect for the
whole product family**.

| Product | What it needs from gono-cloud |
|---|---|
| gono.md | Document sync (WebDAV, implemented) |
| Input Show | Reaching one's own computers across the internet: remote keyboard and mouse, clipboard, screen viewing |
| Future products | Accounts, device directory, device-to-device connections, port forwarding |

Users will have Input Show installed on both their computers and their phones, so "connect to my
own computer remotely, see its screen and control it" is the most direct need.

### 1.2 Requirements

| Requirement | Consumer | Traffic profile | Priority |
|---|---|---|---|
| Device registration, presence, device list | All | Few control messages, long-lived connection | High |
| Keyboard, mouse and clipboard across the internet | Input Show | Small packets, low latency, sensitive to jitter; occasional large clipboard data | High |
| Remote screen viewing | Input Show | 2–6 Mbps video (1080p), long sessions | High |
| Private port forwarding between devices | General | TCP/UDP, variable bandwidth | Medium |
| Public port mapping (frp style) | General | Exposed to the internet, high risk | Low |

### 1.3 Current state

**gono-cloud**

- Rust 1.94, axum 0.8 on tokio, SQLite (sqlx).
- Listens on plain HTTP on loopback only; nginx or Caddy terminates TLS; `base_url` is configured
  explicitly.
- Hardened systemd unit: `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, an empty
  `CapabilityBoundingSet=`, `PrivateDevices=yes`, system call filtering.
- Already in place: accounts, app passwords, Login Flow v2 (with a browser consent page),
  notify_push over WebSocket, the web file UI, the web admin UI.
- The repository plans `crates/protocol` (wire types shared by server and clients) and
  `crates/client/*`; components are released separately; new abilities are advertised through
  capabilities, and released protocol is only ever extended, never changed.

**Input Show's network stack** (`core/crates/inputshow-net`)

- quinn 0.11 (quinn-proto 0.11.19) on tokio.
- rustls 0.23 with ring as the crypto provider, TLS 1.3 only.
- ALPN `inputshow/1`, listening on UDP 24850.
- Every device has a self-signed certificate; authentication is mutual. The handshake accepts the
  peer's certificate, and once it completes, the certificate's SHA-256 fingerprint is compared with
  the paired devices. An unknown fingerprint can only enter the pairing flow, which shows the same
  6-digit code on both sides.
- Three kinds of channels on one connection:
  - Control stream (the first bidirectional stream): key presses, mouse buttons, switching, wheel,
    movement while a button is held; reliable and ordered.
  - Unidirectional streams (from protocol v2): AUX low-priority messages and BULK data (clipboard).
  - QUIC datagrams (RFC 9221): pointer movement while no button is held; may be lost, with sequence
    numbers for loss statistics; falls back to the control stream above the MTU or when the peer
    lacks support.
- Transport parameters: 1 s keep-alive, 5 s idle timeout, 5 s handshake timeout, 256 KB datagram
  send and receive buffers.
- Platforms: macOS, Windows (x64, ARM64), Linux (X11, GNOME and KDE on Wayland, UOS, Kylin,
  deepin), HarmonyOS PCs (can only be controlled); phone apps in development.
- Product promise: direct LAN connections, no account needed, no traffic through the cloud.
- The website lists the installers as not released yet, so **there are no users and no existing
  pairings yet**.

---

## 2. Recommended design

```text
Services     input · clipboard · screen · forward · ...
             (stream types / ALPNs on one connection)
Connection   iroh Endpoint / Connection (noq QUIC, TLS 1.3 with mutual raw public key authentication, end to end)
Paths        LAN direct │ hole-punched direct │ self-hosted iroh-relay (managed by iroh, multipath with automatic switching)
Control      gono-cloud: accounts, device directory, presence, authorization, address lookup, relay access control, audit
```

- Device identity changes from "self-signed certificate plus fingerprint" to iroh's Ed25519 public
  key (`EndpointId`).
- gono-cloud embeds iroh-relay (a `gono-cloud relay` subcommand, which can also run inside
  `serve`) and lets only registered devices use it.
- Devices find each other through address lookup provided by gono-cloud, never through n0's public
  services.
- LAN connections still do not depend on the cloud: mDNS or Input Show's existing discovery hands
  addresses to iroh.

---

## 3. Why iroh

### 3.1 Technical reasons

**1) The hardest and most security-sensitive part already exists and is widely deployed**

NAT traversal, multipath switching, relay fallback and network changes (Wi-Fi ↔ cellular) are the
hardest parts of remote connectivity. iroh's transport, noq, implements:

- QUIC Multipath (draft-ietf-quic-multipath): paths are first-class in QUIC; one connection can hold
  a relay path and a direct path at once and switch between them as conditions change.
- QUIC NAT Traversal (n0's implementation of draft-seemann-quic-nat-traversal): hole punching
  happens inside QUIC, so congestion control and loss detection are aware of it.
- QUIC Address Discovery (draft-ietf-quic-address-discovery): QUIC replaces STUN for learning the
  public address, and the exchange is encrypted.

n0 states that its NAT traversal has been tested on hundreds of thousands of devices running iroh,
and that about 95% of data flows directly in typical use (that ratio must be measured in our own
network conditions, see V8).

**2) What we would have to write without iroh**

Keeping quinn 0.11 and building our own path layer (option A) needs at least:

| Module | Difficulty |
|---|---|
| Custom `AsyncUdpSocket` (path socket) | Coupled to quinn internals; must follow quinn upgrades |
| A virtual address per peer | Hides path switches from quinn, but quinn's congestion control knows nothing about them |
| Separating punch packets from QUIC packets | Cannot rely on the fixed bit (quinn enables `grease_quic_bit` by default) |
| Authenticating punch probes | Prevents forged probes from steering traffic to a wrong address |
| Candidate exchange and path selection | Complex state machine with many edge cases |
| MTU per path | Switching between relay and direct paths can cause MTU black holes |
| Relay protocol (client and server) | Access control, rate limiting, backpressure, loss semantics |
| Watching interfaces and routes | Different on every platform |
| UPnP / PCP / NAT-PMP | Each protocol, and router compatibility |
| Public address discovery | A STUN-like protocol that must resist reflection amplification |

Every item has security-relevant edge cases. Together they are an estimated several months of work
with a high long-term maintenance cost.

**3) Same technology as Input Show, so the migration is bounded**

- Also Rust, tokio and rustls with TLS 1.3; iroh's default feature `tls-ring` uses ring, as Input
  Show does.
- noq is a hard fork of quinn, and its API is close to quinn's. `Connection` offers `open_bi`,
  `open_uni`, `send_datagram`, `max_datagram_size`, `datagram_send_buffer_space`,
  `export_keying_material`, `stats`, `rtt`, `congestion_state`, `paths` and `path_events`;
  `SendStream::set_priority` sets stream priorities.

How Input Show's channels map onto iroh:

| Input Show | iroh API |
|---|---|
| Control stream (bidirectional, reliable, ordered) | `open_bi` / `accept_bi`, highest priority |
| AUX / BULK unidirectional streams | `open_uni` / `accept_uni`, priorities through `set_priority` |
| Pointer datagrams | `send_datagram` / `read_datagram`; `max_datagram_size` decides when to fall back to the control stream |
| Pairing comparison code | `export_keying_material` |
| Video bitrate control (screen viewing) | `stats` / `rtt` / `congestion_state` |
| "Direct / relayed" indicator in the UI | `paths` / `path_events` (exact fields to be verified, see V5) |

**4) Stability commitments since 1.0**

- 1.0 shipped in June 2026 with a locked wire protocol; changes that affect the wire happen only in
  major releases.
- Major and minor versions follow a support schedule; by November 2026 releases reached 1.4.1 at a
  steady pace.
- MSRV 1.91, below gono-cloud's 1.94.

**5) The relay can be self-hosted and embedded in gono-cloud**

The `server` feature of `iroh-relay` can be used as a library:

- `Server` / `ServerConfig` / `RelayConfig`: the relay itself and its HTTP(S) listener.
- `TlsConfig` / `CertConfig` / `AcmeConfig`: own certificates, ACME, or certificates reloaded from
  disk on an interval.
- `QuicConfig`: the QUIC server for QAD (address discovery).
- The `AccessControl` trait: decides which endpoints may use the relay and receives connect and
  disconnect events.
- `Limits` / `ClientRateLimit`: overall and per-client rate limits (the per-client limit can be
  updated live since 1.0.2).
- `RelayMetrics`: relay metrics.
- HTTP endpoints: `/relay` (the main channel), `/ping` and `/generate_204` (network probes).

**6) Address lookup can be replaced entirely**

- The `AddressLookup` trait can be implemented by the application; `MemoryLookup` lets the
  application add and remove addresses itself.
- mDNS lives in a separate crate (`iroh-mdns-address-lookup`) and works on a LAN without the cloud.
- gono-cloud can therefore be the only device directory and hand out addresses only to authorized
  devices.

**7) Identity and end-to-end encryption**

- An `EndpointId` is the device's Ed25519 public key; TLS 1.3 uses raw public keys (RFC 7250) and
  both sides verify each other.
- Dialing by public key unifies identity and address. It is simpler than "self-signed certificate
  plus fingerprint comparison" and equally secure.
- Relays only see ciphertext.

**8) Compatible license**: MIT OR Apache-2.0, the same as gono-cloud.

**9) Room to grow**: custom transports (`unstable-custom-transports`, for example Bluetooth), and
official Swift and Kotlin bindings (not needed for now, since Input Show's core is Rust).

### 3.2 Reasons from gono-cloud's product positioning

**1) gono-cloud's value is the interconnect platform, not the transport**

gono-cloud should provide platform capabilities: accounts, the device directory, authorization,
relays and auditing. The transport does not set the products apart. A mature open-source transport
lets us spend our effort on the product experience: remote screen viewing and control in Input
Show, sync in gono.md.

**2) "The cloud helps devices find each other but is never a source of trust" fits iroh's model**

iroh dials by public key, and whether a connection is trusted depends on that key, not on a server.
Even if gono-cloud or the official hosted service were compromised, it could not impersonate a
device to view a screen or control a computer. For a remote control product this is the most
important security property.

**3) Input Show's privacy promise survives**

- LAN mode needs no account and no cloud, and stays available.
- Remote access is opt-in, and relays only see ciphertext.
- Users who self-host gono-cloud run their own relay too; no third party sees their traffic.
- This requires removing iroh's default dependence on n0's public services (V4).

**4) Friendly to self-hosting**

gono-cloud is a self-hosted product whose install script sets everything up with one command.
iroh-relay can be embedded in the same binary, so self-hosting users deploy nothing extra. For the
official hosted service the same binary runs as `gono-cloud relay` in several regions.

**5) A platform that future products reuse**

A shared connection crate (working name `gono-connect`) gives any future product sign-in, device
discovery, NAT traversal and relaying, as long as it depends on the crate and defines its own ALPN.
If gono.md ever needs device-to-device transfers (LAN sync, large files), it can reuse the same
crate.

**6) Switching now costs the least**

Input Show has not shipped, so there are no users and no pairings. Moving the identity model from
certificate fingerprints to `EndpointId` needs no migration at all. After the release, a switch
would mean migrating existing pairings and keeping old and new versions interoperable, which costs
far more.

**7) The direct-connection rate decides the running cost**

Screen viewing at 1080p takes about 2–6 Mbps, 1–3 GB per hour. Relayed traffic is the largest cost
of an official hosted service. A mature hole-punching implementation directly lowers bandwidth
spending and latency.

### 3.3 "A maintained open-source project is more secure": what it does and does not give us

This is the right direction, but it helps to be clear about what improves and what is not
guaranteed.

**What improves**

- Both options use rustls with TLS 1.3 for encryption and authentication, so there is little
  difference there.
- The real difference is the path layer: hole punching, multipath and relaying are where home-grown
  code most often goes wrong (forged probes, path hijacking, state machine edge cases). iroh has run
  on many devices and keeps getting fixed.
- The less network code we write ourselves, the fewer vulnerabilities we introduce ourselves.

**What is not guaranteed**

- We found no public third-party security audit of iroh or noq.
- noq is maintained mainly by one company, n0, and has a narrower user base than quinn.
- The dependency tree is larger, which grows the attack surface and the supply chain risk.
- The default configuration contacts n0's public services and must be turned off explicitly.

These are covered by the checks in section 7 (V4, V9, V10).

---

## 4. Alternatives

| Option | Description | Pros | Cons | Verdict |
|---|---|---|---|---|
| A. quinn 0.11 + own path layer | Path socket, hole punching and a custom relay below the existing `inputshow-net` | Identity model unchanged; path layer protocol fully our own; few dependencies | Largest effort (months); all security-sensitive code maintained by us; quinn is unaware of path switches | Fallback if V1 fails |
| **B. iroh 1.x** | iroh as the connection layer; gono-cloud as control plane and self-hosted relay | Mature path layer; native multipath; 1.0 stability commitment; self-hostable relay | New identity model; tied to n0's release pace; HarmonyOS unverified; defaults depend on n0 services | **Recommended** |
| C. rust-libp2p | QUIC + DCUtR hole punching + circuit relay v2 | Feature-complete, large community | Designed for the libp2p ecosystem, heavy abstractions; identity and protocol stack do not fit our needs; large binaries | Not recommended |
| D. WebRTC (str0m / webrtc-rs) | ICE + DTLS + SCTP/SRTP | Works in browsers; mature media transport | Built for audio and video conferencing, heavy stack; every endpoint is a native app, so browser support buys nothing | Only if screen viewing in a browser becomes a requirement |
| E. WireGuard / virtual network interface (Tailscale style) | Layer 3 virtual network | Transparent to applications | Needs TUN and system privileges, VPN permission on phones; does not fit the products | Not recommended |
| F. Own implementation modeled on RustDesk / ZeroTier / frp | Build our own after their designs | Proven designs | RustDesk's server is AGPL and ZeroTier is not permissively licensed, so no code can be copied; highest cost | Use as design reference only |

---

## 5. Target architecture with iroh

### 5.1 gono-cloud

| Component | Content |
|---|---|
| Device directory | New table `devices`: `id`, `user_id`, `endpoint_id`, `product` (input-show / gono-md / …), `platform`, `name`, `created_at`, `last_seen_at`, `revoked_at`, remote access policy |
| Authorization | Who may connect to whom: within one account by default; unattended access enabled per device |
| Device registration | Reuses the Login Flow v2 browser consent; the device signs a server nonce with its `SecretKey` to prove possession of the key |
| Control channel | gono's own WebSocket (for example `/gono/v1/ws`), not notify_push (which is Nextcloud's protocol). Carries presence, connection requests, addresses and revocations |
| Address lookup | Devices implement `AddressLookup` by asking gono-cloud over the control channel; the server only returns addresses of authorized devices |
| Relay | Embeds `iroh_relay::server::Server`; implements `AccessControl` to admit only registered, unrevoked `EndpointId`s; `ClientRateLimit` for rate limiting |
| Audit | Records who connected to which device, when, directly or relayed, for how long and how much traffic; never content |
| UI | The account page lists the user's devices, their presence, and revocation; the admin UI shows relay load and sessions |

### 5.2 Devices

- A shared crate, `gono-connect`:
  - Configures the iroh `Endpoint`: a custom `RelayMap`, gono's `AddressLookup`, optional mDNS; none
    of n0's presets or public services.
  - The control channel client: sign-in, presence, connection requests, confirmations.
  - Exposes only "connect to a device / accept connections" to products. Product code never depends
    on iroh's multipath API directly, which limits the impact of API changes.
- Input Show's `inputshow-net` moves onto iroh; the ALPN becomes `inputshow/2` (the identity model
  changes, so it does not interoperate with v1; since nothing has shipped, a plain bump is enough).

### 5.3 Connection flow

1. Both devices are online, connected to gono-cloud's control channel and to the self-hosted relay
   (iroh keeps the relay connection up).
2. The controlling device (for example a phone) picks computer X from the device list and asks
   gono-cloud to connect.
3. gono-cloud checks authorization (same account, X allows remote access), forwards the request to
   X and provides each side's addresses to the other's address lookup.
4. X applies its policy: by default it asks the user to confirm on the spot; a device with
   unattended access enabled accepts directly.
5. The controlling device dials X's `EndpointId`. iroh connects through the relay first and punches
   holes in the background; once that succeeds it switches to the direct path and keeps the relay
   path as a fallback.
6. Once connected, both sides check the peer's `EndpointId` against their local list of paired
   devices (gono-cloud plays no part in this step).
7. X shows "being controlled by device …" with a one-click disconnect; gono-cloud records the
   session in the audit log.

### 5.4 Identity, pairing and trust

- **Pairing stores the peer's `EndpointId`**, in place of today's certificate fingerprint.
- **LAN pairing**: keeps the existing 6-digit code flow.
- **Remote pairing** (two devices that have never shared a LAN):
  - The target accepts an unknown `EndpointId` only after the user puts it into pairing mode, and
    the number of attempts is limited.
  - The 6-digit code must be derived from this connection's `export_keying_material`; each side
    computes it and the user compares them. A code generated by one side and typed in on the other
    is not acceptable: over a relay, a man in the middle could impersonate either side.
- **gono-cloud does not make devices of one account trust each other automatically by default.**
  Otherwise a compromised server could slip in a fake device. It can be offered as an opt-in
  convenience with a clear warning.
- **Revocation**: gono-cloud can tell devices that a device was revoked (revocation is the safe
  direction: a server can only remove trust, never add it), and the relay's `AccessControl` refuses
  the revoked device immediately.

### 5.5 Removing the dependence on n0's infrastructure

- Do not use `presets::N0`; start from the minimal preset and configure `RelayMode` and a custom
  `RelayMap` explicitly.
- Do not use `PkarrPublisher::n0_dns()` or any other constructor that points at n0's public
  services.
- `iroh-dns` is a mandatory dependency of iroh; confirm that it never contacts n0's DNS service when
  not configured to.
- Network probes (net_report) go only to our own relays (`/ping`, `/generate_204`).
- Metrics (the `metrics` feature) stay local and are never reported.
- Packet captures decide (V4).

### 5.6 Deployment

| Shape | Components |
|---|---|
| Self-hosted (single host) | `gono-cloud serve` provides both the control plane and the relay; the relay's `/relay` goes through the existing nginx (to be verified), QAD needs one public UDP port |
| Official hosted service | A central control plane; `gono-cloud relay` in several regions, whose access control asks the control plane or checks tickets the control plane signed |

The existing systemd unit allows UDP and needs no extra privileges for ports above 1024; the
relay's unit can reuse the existing hardening.

### 5.7 Changes to Input Show's protocol

- **Two sets of transport parameters**: the LAN keeps today's values; remote connections use a
  10–15 s handshake timeout and a 15–30 s idle timeout.
- **Key release separate from the connection timeout**: "release all keys after a disconnect" uses
  an application-level 2 s heartbeat, so the connection itself can be more tolerant.
- **Absolute pointer coordinates**: screen viewing sends absolute coordinates mapped onto the
  remote screen; the viewer draws the cursor locally, and the target only sends the cursor's shape
  and position.
- **Text input**: a phone's on-screen keyboard needs a "commit text" message; the physical key model
  does not fit.
- **Screen stream**: a new SCREEN unidirectional stream type; the control stream keeps the highest
  priority; at most 1–2 video frames in flight, dropping frames rather than queueing them.
- **Capability negotiation**: reuse the version mechanism of PROTOCOL.md and add capability flags
  for remote, screen, absolute pointer and text input.

---

## 6. Risks and mitigations

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | Build or runtime failure on HarmonyOS (platform-specific code in netwatch, portmapper, noq-udp) | Blocking: HarmonyOS devices could not talk to other devices over iroh | Check V1; disable `portmapper`; send patches upstream; at worst fall back to option A |
| R2 | Default connections to n0's public relays and discovery | Breaks Input Show's privacy promise | Do not use the N0 preset; confirm with packet captures (V4) |
| R3 | noq is maintained mainly by n0 | Long-term maintenance risk | Pin versions; follow releases and the community; keep a fork plan; isolate behind `gono-connect` |
| R4 | No public third-party security audit | Unknown vulnerabilities | Review critical paths ourselves in V9 (TLS verification, relay trust model); cargo-audit; follow advisories; commission an audit if needed |
| R5 | The multipath API is young and may change | Upgrade cost | Use it only inside `gono-connect`; product code never depends on it |
| R6 | Larger dependency tree and binaries | Attack surface, app size on phones | Disable unneeded features; measure in V12 |
| R7 | The path layer and relay protocol are no longer our own | Less flexibility | Keep our own definitions in the control channel, authorization rules and application protocols |
| R8 | Dependency conflicts or deployment mismatch between iroh-relay and gono-cloud | Integration cost | Check embedding, static musl builds and the nginx reverse proxy in V6 |
| R9 | Network conditions in China: carrier-grade NAT (CGNAT) is common and some networks throttle UDP | Lower direct rate than n0's figures, higher bandwidth cost | Measure in V8; place relays close to users; cap bitrate on relayed paths |
| R10 | Background restrictions on phones | Phones as controlled devices are not realistic | Desktops are the controlled devices; phones control and view |
| R11 | The identity model changes | Input Show's protocol and pairing logic change | Nothing has shipped, so there is no migration; bump the ALPN to `inputshow/2` |

---

## 7. What to verify

Each check lists its goal, method, pass criteria, and whether it can block the decision.

### V1 Building and running on HarmonyOS (blocking)

- **Goal**: confirm that iroh works on HarmonyOS PCs. iroh connections only interoperate with iroh,
  so HarmonyOS cannot stay on quinn on its own.
- **Method**:
  1. Install the OpenHarmony SDK (clang and sysroot) and run
     `rustup target add aarch64-unknown-linux-ohos`.
  2. Write a minimal spike crate that depends on iroh 1.4 and build it with the default features and
     with `portmapper` disabled.
  3. Run it on a real device: bind UDP 24850; connect directly to a macOS device on the LAN; connect
     through the self-hosted relay; turn Wi-Fi off and on again and watch network change detection.
- **Watch for**:
  - Whether ring builds with OpenHarmony's clang.
  - How noq-udp's socket options (GSO, GRO, ECN) behave on HarmonyOS.
  - Whether the system interfaces netwatch uses to watch interfaces and routes (netlink and others)
    are available inside the HarmonyOS application sandbox.
  - Whether portmapper works, and whether disabling it affects anything else.
  - Whether iroh-dns's way of reading the system DNS configuration applies.
- **Pass**: builds without changes, or with a few patches that can go upstream; all three
  connection kinds (LAN, relay, hole-punched) work.

### V2 No regression on the LAN (blocking)

- **Goal**: the LAN is Input Show's core use; a new transport must not make it feel worse.
- **Method**: on a spike branch of the Input Show repository, move the three channels of
  `inputshow-net` onto iroh. Compare with the quinn version on the same hardware and network:
  - pointer datagram one-way latency, p50 and p99 (measured with timestamp echoes);
  - key press latency on the control stream;
  - BULK throughput (for example a 10 MB image on the clipboard);
  - CPU usage at a 1000 Hz mouse polling rate;
  - memory usage;
  - connection setup time on the LAN;
  - binary size increase.
- **Pass** (suggested thresholds, to be settled during the evaluation): p99 latency grows by less
  than 1 ms; CPU usage grows by less than 10%; no noticeable change in connection setup time.

### V3 Builds and system permissions on every platform

- **Goal**: confirm that every target platform builds, and understand each platform's network
  permissions.
- **Method**:
  - Build the spike for macOS (Apple silicon, Intel), Windows (x64, ARM64), Linux (glibc; X11 and
    Wayland only affect input, not networking), iOS and Android.
  - iOS: the local network permission prompt and what happens to connections in the background.
  - Android: Doze and network change callbacks.
  - Windows: the firewall prompt for the fixed port 24850.
- **Pass**: everything builds; permission behavior is documented well enough for user
  documentation.

### V4 No dependence on n0's services (blocking, part of the product promise)

- **Goal**: keep the traffic and metadata of Input Show and self-hosted gono-cloud away from third
  parties.
- **Method**:
  1. Create the endpoint from the minimal preset: a custom `RelayMap` pointing at the self-hosted
     relay, gono's `AddressLookup` plus mDNS, and no n0 constructors at all.
  2. Capture traffic with tcpdump or Wireshark (plus Little Snitch on macOS), DNS queries included,
     across a cold start, 30 minutes idle, setting up a connection, a network change and a
     self-hosted relay outage.
  3. Run a fully offline test with only the LAN, and confirm that mDNS discovery and direct
     connections work.
- **Pass**: no DNS queries or connections to n0's public relays, public DNS or any other n0 service
  (judged against n0's domain names in the captures); full LAN functionality offline.

### V5 Does the API cover our needs?

- **Goal**: confirm that everything Input Show and later features need is there, and find
  workarounds for what is missing.
- **Check each**:
  - `export_keying_material`: both ends derive the same material over a relayed connection, so it
    can produce the pairing comparison code.
  - `SendStream::set_priority`: its meaning under multipath; whether the control stream always goes
    before BULK and video.
  - `send_datagram` / `max_datagram_size`: the size limits on relay and direct paths; datagram loss
    at the moment of a path switch.
  - `paths` / `path_events`: whether relay and direct paths can be told apart, for the UI and logs.
  - `stats` / `rtt` / `congestion_state`: whether they can drive bitrate control for screen
    viewing.
  - Whether the endpoint can bind UDP 24850 (the LAN firewall documentation relies on a fixed
    port).
  - Whether transport parameters (idle timeout, keep-alive) can be set per connection, to separate
    the LAN and remote profiles.
  - Serving several ALPNs on one endpoint (routing in the `protocol` module).
- **Pass**: all needs are met, or each gap has a clear, acceptable workaround.

### V6 Self-hosted relay embedded in gono-cloud

- **Goal**: confirm that the relay can be deployed and managed the gono-cloud way.
- **Method**:
  1. Build a spike in gono-cloud, not to be merged: a `gono-cloud relay` subcommand that embeds
     `iroh_relay::server::Server`.
  2. Check dependency conflicts (axum 0.8, hyper, tokio, rustls versions); build a static musl
     binary with cargo-zigbuild; record the binary size increase.
  3. Put the relay behind nginx: whether the HTTP upgrade of `/relay` passes the reverse proxy, how
     to configure the relay without its own TLS, and how to expose the UDP port for QAD.
  4. Implement `AccessControl` to admit only registered, unrevoked `EndpointId`s; measure how fast a
     revocation takes effect.
  5. Configure `Limits` / `ClientRateLimit` and verify per-device rate limiting.
  6. Show `RelayMetrics` in the admin UI.
  7. Run under the existing systemd hardening.
  8. Load test: memory for 1000 idle clients, CPU per Gbps relayed.
- **Pass**: embeddable, statically buildable, runs behind nginx; access control and rate limiting
  work; resource usage as expected.

### V7 Address lookup and offline mode

- **Goal**: gono-cloud is the only device directory, while LAN mode stays independent of the cloud.
- **Method**:
  - Implement an `AddressLookup` on top of the control channel: measure lookup latency, decide on
    caching, check behavior while gono-cloud is unreachable.
  - On the LAN, compare `iroh-mdns-address-lookup` with Input Show's existing discovery feeding
    `MemoryLookup`, and pick one.
  - Confirm that unauthorized devices cannot obtain other devices' addresses.
- **Pass**: remote and LAN discovery both work; a gono-cloud outage does not affect the LAN.

### V8 NAT traversal in practice

- **Goal**: real direct-connection rates and switch times, for capacity planning and product
  expectations.
- **Method**:
  - **Test matrix** (Linux network namespaces with nftables): endpoint-independent mapping (full
    cone), address-restricted, port-restricted, symmetric NAT (one side / both sides), double NAT,
    CGNAT (100.64.0.0/10), UDP blocked (relay only), IPv6 only, dual stack, hairpinning.
  - **Real networks**: home broadband from China Telecom, China Unicom and China Mobile, 4G/5G,
    campus and corporate networks, cross-border connections.
  - **Metrics**: time until first usable (relayed), time until direct, share of direct
    connections, time to fall back to the relay when the direct path breaks, interruption during
    Wi-Fi ↔ cellular handover, input latency relayed and direct.
- **Pass**: no hard threshold; the results set product expectations and the bandwidth budget. Two
  devices behind the same NAT must connect directly, though.

### V9 Security review

- **Goal**: form our own judgment of the critical code and the trust model before adopting it.
- **Method**:
  - Dependency checks: cargo-deny (licenses, advisories, duplicate dependencies), cargo-audit; count
    unsafe code in the dependency tree (cargo-geiger).
  - Read iroh's security policy and disclosure channel; look at past advisories and response
    times.
  - Review the TLS verification code (`iroh/src/tls/verifier.rs`, `resolver.rs`): how raw public
    keys are compared and how the expected identity is passed in.
  - Walk through the threat model:
    - A malicious relay can drop and delay packets; can it inject forged addresses? How far can
      addresses provided by a relay be trusted?
    - A malicious or compromised gono-cloud cannot impersonate devices; it can deny service and lie
      about addresses. Is the worst outcome a failure to connect?
    - A malicious device on the LAN: is the pairing flow safe?
    - A leaked device key: is revocation complete?
  - Find out whether noq and iroh are fuzzed.
- **Pass**: no unresolved serious issues; the trust model goes into the M0 threat model document.

### V10 Maintenance and governance

- **Goal**: judge whether the long-term dependency is sustainable.
- **Method**: look at the release pace from 1.0 (2026-06) to 1.4.1 (2026-11); read the support
  policy for major and minor versions; count active maintainers of iroh and noq and their issue
  response times; understand how noq relates to upstream quinn; estimate the cost of maintaining our
  own fork if needed.
- **Pass**: actively maintained, with support windows that cover Input Show's release cycle; a
  workable fork plan.

### V11 Phones

- **Goal**: know what phones can and cannot do.
- **Method**:
  - iOS: when connections are suspended in the background, how fast they reconnect in the
    foreground; the local network permission.
  - Android: behavior under Doze and battery saving; network change callbacks.
  - Battery cost of the 1 s keep-alive when it only runs during sessions.
- **Pass**: an acceptable experience for phones as controllers and viewers; limitations go into the
  product documentation.

### V12 Dependencies, builds and size

- **Goal**: keep the supply chain and binary size under control.
- **Method**:
  - Keep `tls-ring`, as Input Show does; avoid `tls-aws-lc-rs` (it needs cmake and other tools,
    which makes HarmonyOS and musl builds harder).
  - Evaluate each default feature: `metrics`, `portmapper`, `fast-apple-datapath` (find out what it
    does); disable the ones we do not need.
  - Check that MSRV 1.91 and edition 2024 fit Input Show's toolchain.
  - Record the binary size increase on every platform.
- **Pass**: a settled feature list; an acceptable size increase.

---

## 8. Verification plan and deliverables

### 8.1 Schedule (about two weeks)

| When | What |
|---|---|
| Days 1–3 | V1 HarmonyOS, V12 dependencies and builds |
| Days 3–5 | V2 LAN performance, V5 API |
| Days 6–8 | V4 no n0 dependence, V6 self-hosted relay, V7 address lookup |
| Days 8–9 | V8 NAT traversal |
| Days 9–10 | V3, V9, V10, V11; write the decision |

V1 is the largest uncertainty and comes first. If V1 fails, stop and evaluate the fallback before
doing anything else.

### 8.2 Deliverables

- A spike branch in the Input Show repository (`inputshow-net` on iroh).
- A spike in gono-cloud (embedded iroh-relay, not merged).
- A performance comparison (V2).
- Packet captures (V4).
- NAT test scripts and results (V8).
- Security review notes (V9).
- The decision: adopt, do not adopt, or adopt with conditions, and why.

### 8.3 Decision rules

- V1, V2 and V4 must pass.
- If V5 finds a missing API, continue only with an acceptable workaround.
- Pause if V9 finds an unresolved serious issue.
- The other checks refine the design and do not block the decision.

---

## 9. Fallback if a check fails

| Case | Fallback |
|---|---|
| V1 fails (HarmonyOS) | Size the patches first: if small, send them upstream and use a pinned fork meanwhile; if large, fall back to option A (quinn 0.11 + own path layer). Mixing is not possible: HarmonyOS on quinn and other platforms on iroh cannot talk to each other |
| V2 fails (LAN performance) | Find the cause first (congestion control, multipath overhead, socket options) and report it upstream; fall back to option A if it cannot be solved soon |
| V4 fails (n0 dependence) | Turn it off through features or patches; if that is not possible, do not adopt iroh |

Key points of option A, kept for reference: implement a custom `AsyncUdpSocket` below quinn 0.11;
give each peer a fixed virtual address; separate punch packets from QUIC packets by a fixed prefix;
authenticate probes with an HMAC keyed by material from `export_keying_material`; run the relay over
gono-cloud's WebSocket and address it by relay session ID.

---

## 10. Milestones after the decision (assuming iroh)

1. **M0 Specification and threat model**: control channel messages, device registration,
   authorization rules, auditing, the remote pairing comparison code, relay access control, the
   trust model.
2. **M1 Device directory**: the device table in gono-cloud, registration (Login Flow v2), the
   control channel, presence, the account page and the admin UI.
3. **M2 Keyboard and mouse across the internet**: the self-hosted relay and address lookup; Input
   Show on iroh (no LAN regression); keyboard, mouse and clipboard across the internet.
4. **M3 Traversal tuning**: the NAT test matrix in CI, a direct/relayed indicator in the UI, tuning
   based on V8.
5. **M4 Remote screen viewing**: computers as controlled devices; on-the-spot confirmation, an
   indicator while being controlled, auditing; adaptive bitrate; phones as controllers and viewers.
6. **M5 Port forwarding and other products**: private port forwarding between devices (n0's
   dumbpipe is a possible reference); gono.md receives real-time events over the control channel;
   multi-region relays for the official hosted service.

---

## 11. Open questions

- Will there be an official hosted service, or only self-hosting? This affects relay deployment,
  quotas and billing.
- When does two-factor authentication for accounts ship? It must be in place before remote control.
- Should "devices of one account trust each other automatically" be offered as an option?
- Is screen viewing in a browser needed? If so, WebRTC comes in.
- Does gono.md need direct device-to-device connections (LAN sync, large file transfers)?
- Should HarmonyOS devices be reachable remotely as well (today they can only be controlled)?
- Bandwidth quotas and rate limiting policy for relays.

---

## 12. References

- [Iroh 1.0 - Dial Keys, not IPs](https://iroh.computer/blog/v1)
- [noq, noq, who's there?](https://iroh.computer/blog/noq-announcement)
- [iroh 1.0.3 - Steadier Connections](https://iroh.computer/blog/iroh-1-0-3)
- [n0-computer/iroh (GitHub)](https://github.com/n0-computer/iroh)
- [iroh documentation (docs.rs)](https://docs.rs/iroh/latest/iroh/)
- [iroh::endpoint::Connection](https://docs.rs/iroh/latest/iroh/endpoint/struct.Connection.html)
- [iroh::address_lookup](https://docs.rs/iroh/latest/iroh/address_lookup/index.html)
- [iroh_relay::server](https://docs.rs/iroh-relay/latest/iroh_relay/server/index.html)
- [iroh Cargo.toml (features and dependencies)](https://docs.rs/crate/iroh/latest/source/Cargo.toml.orig)
- [noq (docs.rs)](https://docs.rs/crate/noq/1.2.0)
- [Rust platform support: OpenHarmony](https://doc.rust-lang.org/nightly/rustc/platform-support/openharmony.html)
- [n0-computer/net-tools (netwatch, portmapper)](https://awesome.ecosyste.ms/projects/github.com%2Fn0-computer%2Fnet-tools)
- [Input Show](https://input.show)
