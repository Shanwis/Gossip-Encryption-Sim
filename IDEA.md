# Gossip-Based Secure Group Messaging Simulator

> **Refined Project Specification & V1 Architecture**  
> **Status:** Approved Architecture (V1 Scope)  
> **Focus:** Applied Cryptography, Epidemic Gossip Protocols, Linux Network Namespaces (`netns`), Network Traffic Control (`tc/netem`), Attack Simulation, and Experimental Systems Analysis.

---

## 1. Project Overview

The **Gossip-Based Secure Group Messaging Simulator** is a distributed systems and applied cryptography testbed designed to study and evaluate secure multi-party communication over arbitrary network topologies under realistic failure modes and active adversarial conditions.

Each participant is modeled as an independent daemon running within an isolated **Linux Network Namespace (`netns`)**. Every pair of adjacent nodes shares a dedicated point-to-point `veth` link managed by the simulator (one link per topology edge). 

Key capabilities include:
- **Direct node-to-node messaging** (isolated data-plane verification);
- **Cryptographically protected group messaging** via authenticated encryption (`AES-256-GCM`);
- **Epidemic gossip-based propagation** of group state, membership transitions, and rotated key material;
- **Strict group epoch progression** with forward/backward secrecy objectives — experimental goals demonstrated under test (§10.2), not formal guarantees;
- **Cryptographic identity and key management** using `Ed25519` for signatures and `X25519` for key agreement;
- **Kernel-level network impairment injection** (`tc/netem`) including packet loss, latency, jitter, and network partitions;
- **Adversarial attack orchestration** (packet tampering, replay, message forgery, node compromise, and partition split-brain tests);
- **Out-of-band node inspection and telemetry** via Unix Domain Sockets;
- **Structured JSONL logging and automated experimental analysis** with Pandas/Matplotlib.

---

## 2. One-Line Project Definition

> A Linux namespace-based distributed testbed where independent node processes exchange encrypted group messages using AES-256-GCM, authenticate state transitions via Ed25519, propagate membership and key rotations via epidemic gossip, isolate control from data planes, and evaluate cryptographic and epidemic-dissemination resilience under kernel-level network degradation and active attacks.

---

## 3. System Architecture

```text
                          CLI / Experiment Orchestrator
                                             |
                    +------------------------+------------------------+
                    | (Out-of-Band Control via Unix Sockets)          |
                    v                                                v
          +----------------------+                        +---------------------+
          | Topology & Link      |                        |    Attack Engine    |
          | Manager (netns/veth) |                        | (netem / link cut)  |
          +----------+-----------+                        +----------+----------+
                     | ip netns / ip link / tc                        |
=====================|================================================|=========================
KERNEL SPACE         v                                                v
     one veth pair per graph edge, one /31 link per pair      [ tc/netem qdiscs ]
       vlk0a 10.200.0.0/31        vlk1a 10.200.0.2/31       [ on link veth ends ]
              |                            |                         |
==============|============================|===================================================
USER          v                            v                         v
SPACES [ netns alice ]  =  [ netns bob   ]  =  [ netns charlie ]
       |  Node Daemon  |   |  Node Daemon  |   |  Node Daemon   |
       |  - Engine     |   |  - Engine     |   |  - Engine      |
       |  - Gossip     |   |  - Gossip     |   |  - Gossip      |
       |  - Crypto     |   |  - Crypto     |   |  - Crypto      |
       |  - UDS IPC    |   |  - UDS IPC    |   |  - UDS IPC     |
       +--------------+    +--------------+    +----------------+
         alice-bob edge      bob-charlie edge
      (gossip relays updates edge-by-edge at the application layer)

                     Structured JSONL Logs
```

### Architectural Separation: Control Plane vs. Data Plane

A foundational design requirement is the **strict separation of the control plane from the data plane**:

1. **Data Plane (Simulated Network):**
   - Transports application-level direct messages, group messages, and epidemic gossip updates.
   - Runs exclusively over assigned `veth` interfaces attached to the virtual network.
   - Subject to simulated delay, packet loss, bandwidth bottlenecks, and complete network partitions via `tc/netem` and packet filtering.

2. **Control Plane (Management & Telemetry):**
   - Transports CLI inspection commands (`gossip-sim node show alice`), operational commands (`group join`, `send`), and attack triggers.
   - Operates over dedicated **Unix Domain Sockets** located on the host filesystem (e.g. `/tmp/gossip-sim/sockets/{node_id}.sock`).
   - **Crucial Benefit:** Because Unix Domain Sockets bypass the network namespace's IP stack and routing tables, the CLI can inspect, query, and command a node even when that node is isolated behind a 100% packet-loss network partition or degraded by latency.

---

## 4. Virtual Networking & Topology Enforcement

### 4.1 Namespace and Per-Edge Virtual Link Topology
- Each simulated node runs within an independent Linux network namespace (`ip netns add netns-{id}`); its daemon executes inside via `ip netns exec`.
- For every undirected topology edge $(u, v) \in E$, the manager creates exactly one `veth` pair with one end in each node's namespace — a dedicated point-to-point link with its own `/31` subnet (RFC 3021) carved from `10.200.0.0/16` by a deterministic link-index allocator (sorted node IDs; the lower ID takes the `.0` address).
- Interface names respect the kernel `IFNAMSIZ` limit (15 chars): `vlk{n}a` / `vlk{n}b` for link index $n$ (never `veth-alice-charlie`-style names — those silently fail to create).
- The daemon binds its TCP data port on all of its link addresses. The peer table maps neighbor `node_id` → remote link address + port.

### 4.2 Topology Enforcement by Construction (No Flat L2, No Filter Rules)
With one link per edge there is no shared Layer-2 segment: non-adjacent nodes have **no network path at all**, so the topology is enforced by construction rather than by filtering. This eliminates the failure modes of the shared-bridge design:
- No dependency on `br_netfilter` (`net.bridge.bridge-nf-call-iptables=1`) — without it, `iptables FORWARD -m physdev` adjacency rules silently never match bridged traffic and topology enforcement degrades to a no-op;
- No ARP/broadcast flooding leaks across non-edges (flooded frames bypass `--physdev-out` pair rules on a shared bridge);
- No $O(n^2)$ rule tables (the flat-bridge approach needs ~$|V|^2$ filter rules and fights the 100-node scalability goal); kernel resource usage here is $O(E)$.
- Multi-hop reachability is deliberately absent at the network layer: epidemic gossip provides logical multi-hop dissemination by relaying updates edge-by-edge at the application layer — the very behavior under study.

> **Rejected alternative (recorded for the report):** shared Linux bridge `br-sim0` + `iptables -m physdev` adjacency filtering + `ebtables`. If a shared-medium narrative is required, `br_netfilter` MUST be enabled and broadcast filtering specified explicitly — otherwise the filter rules are inert.

### 4.3 Network Degradation via `tc/netem` (Per-Link Granularity)
Impairment applies to a specific edge by shaping one or both ends of its `veth` pair, so a "lossy alice–bob link" is expressible without collateral damage to alice's other links:
- **Packet Loss:** `tc qdisc add dev vlk0a root netem loss 10%`
- **Latency & Jitter:** `tc qdisc add dev vlk0a root netem delay 100ms 20ms distribution normal`
- **Packet Reordering & Duplication:** `tc qdisc add dev vlk0a root netem reorder 25% 50% duplicate 2%`
- **Per-Node Impairment:** the `--node` CLI variant applies the qdisc to every incident link end of that node.
- **Link Failure / Network Partition:** bring the link down (`ip link set vlk0a down`); a partition across the cut $(A, B)$ brings down every edge crossing the cut. Healing restores the links.

### 4.4 Dynamic Topology & Crash-Safe Lifecycle
- Edges can be added or removed at runtime (`gossip-sim link add|remove alice bob`), creating/destroying `veth` pairs on demand — all state changes are $O(E)$.
- The orchestrator records every created resource (netns, links, qdiscs) in a state file; `gossip-sim destroy` tears everything down idempotently; `SIGINT`/`SIGTERM` handlers and test fixtures guarantee cleanup even on crash or assertion failure.

---

## 5. Cryptographic Design & Key Management

### 5.1 Cryptographic Primitives

| Component | Primitive | Specification | Purpose |
|---|---|---|---|
| Identity & Authentication | **Ed25519** | RFC 8032 | Long-term node identity, signing state updates and certificates |
| Pairwise Key Agreement | **X25519** | RFC 7748 | Pairwise Diffie-Hellman key exchange for key distribution |
| Symmetric Group Encryption | **AES-256-GCM** | NIST SP 800-38D | Authenticated encryption with associated data (AEAD) for group messages |
| Key Derivation | **HKDF-SHA256** | RFC 5869 | Deriving wrap keys, sub-keys, and pairwise secrets |
| Key Wrapping | **AES-256-KeyWrap** | RFC 3394 | Encrypting fresh group epoch keys for authorized recipients (sole wrap mechanism; the AES-GCM alternative is dropped) |
| Cryptographic Hash | **SHA-256** | FIPS 180-4 | Digest calculations, update IDs, and public key fingerprints |

### 5.2 Guaranteed Multi-Sender Nonce Partitioning (AES-256-GCM)
In a group setting where all active members share the same epoch symmetric key ($K_{\text{epoch}}$), standard sequential counter nonces cause **immediate catastrophic key failure** (GCM IV reuse under one key) if two nodes ever emit the same IV.

$$\text{Nonce (96 bits)} = \underbrace{\text{Sender Prefix (32 bits)}}_{\text{Admin-assigned uint32, collision-checked}} \parallel \underbrace{\text{Monotonic Counter (64 bits)}}_{\text{Per-node 8-byte big-endian counter}}$$

- **Sender prefix:** assigned by the group Admin at admission from `SHA256("gossip-sim-v1:sender-prefix:v1|" || group_id || sender_id)[0:4]`, **verified unique against every current member** (salted re-derivation on collision), and published in the signed `GROUP_UPDATE` member map. Uniqueness is a *guarantee* enforced by the single committer — deliberately not left to hash probability: a bare 32-bit prefix collides with probability $\approx n^2/2^{33}$ (≈$1.2 \times 10^{-6}$ at 100 senders), which is small but (a) makes the old "mathematical partitioning" claim false and (b) is an unacceptable IV-reuse risk for AES-GCM.
- **Counter:** one monotonic counter per (group, epoch), incremented before each send; the first message of an epoch carries counter `1`; exhaustion triggers rekey rather than wraparound.
- **Associated Authenticated Data (AAD):** Every group message binds unencrypted envelope metadata into the GCM tag:
  $$\text{AAD} = \text{"v1|"} \parallel \text{group\_id} \parallel \text{"|"} \parallel \text{epoch} \parallel \text{"|"} \parallel \text{sender\_id} \parallel \text{"|"} \parallel \text{counter}$$
  Any tampering with sender ID, epoch, or counter invalidates the GCM authentication tag. All hashed/derived concatenations (this AAD, `update_id`, HKDF `info`) follow the canonical encoding rules of `docs/protocol.md` §3.1 (validated identifier charset + version-tagged delimiters), so field boundaries are unambiguous.

### 5.3 Forward and Backward Secrecy via Epoch Key Rotation
When membership changes (a member joins or is removed), a new epoch $e+1$ must be established:
1. **Removed Member Protection (Forward Secrecy):** A removed member must not possess the new group key $K_{e+1}$ or be able to derive it from historical keys.
2. **New Member Protection (Backward Secrecy):** A newly joined member must not be able to decrypt past messages from epochs $0 \dots e$.
3. **No Key Chaining:** A simple hash chain ($K_{e+1} = \text{HKDF}(K_e)$) is strictly prohibited. $K_{e+1}$ is generated from a cryptographically secure random source (CSPRNG):
   $$K_{e+1} \leftarrow \text{CSPRNG}(256\text{ bits})$$

### 5.4 Key Distribution & Ephemeral Wrapping (HPKE-lite)
To distribute $K_{e+1}$ to all authorized members without vulnerability to static key compromise:
1. The group admin generates an **ephemeral X25519 keypair** $(sk_{\text{eph}}, pk_{\text{eph}})$.
2. For each authorized member $M_i$ with pinned long-term public key $pk_{M_i}$:
   $$\text{SharedSecret}_i = \text{X25519}(sk_{\text{eph}}, pk_{M_i})$$
   $$\text{WrapKey}_i = \text{HKDF-Expand}(\text{SharedSecret}_i, \text{info}=\text{"gossip-sim-v1:gossip-wrap:v1|"} \parallel \text{group\_id} \parallel \text{"|"} \parallel (e+1), 32)$$
   $$\text{EncryptedKey}_i = \text{AES-256-KW}(\text{WrapKey}_i, K_{e+1})$$
3. The admin publishes $pk_{\text{eph}}$ and the map of encrypted key blobs $\{ M_i: \text{EncryptedKey}_i \}$ within the signed `GROUP_UPDATE` message.
4. Each member extracts only its own encrypted key, computes the shared secret using its private key $sk_{M_i}$ and the update's $pk_{\text{eph}}$, unwraps $K_{e+1}$ (AES-KW integrity-checked), and verifies the payload.

### 5.5 Identity Distribution & Roster Pinning
Public-key trust is established **out of band by the orchestrator** — never by first-seen bootstrap (a spoofable first update would otherwise let an attacker pin a fake admin):
1. At `gossip-sim init`, the orchestrator generates each node's Ed25519/X25519 keypairs (or collects self-generated public keys over UDS) and writes a **roster manifest** `roster.json`: `node_id` → `{ed25519_pubkey, x25519_pubkey, fingerprint}`, with `fingerprint = SHA256("gossip-sim-v1:fingerprint:v1|" || ed25519_pubkey || "|" || x25519_pubkey)` (hex).
2. The manifest is distributed to each node's state directory before its daemon starts; daemons pin it read-only and verify every security-relevant artifact (admin signatures, key wraps, HELLO frames) against the pinned keys.
3. `crypto/certificate.py` provides self-signed identity metadata binding `node_id` ↔ public keys — a display/metadata layer only (see `Initial_IDEA.md` §6). The roster manifest is the actual trust anchor; no PKI or chain validation in V1.

---

## 6. Group Membership & Consensus Model

### 6.1 The Gossip-Consensus Problem
Epidemic gossip dissemination is an *eventually consistent* best-effort distribution protocol. Group key transitions, however, require a *strictly linear state sequence* ($e \to e+1$). Uncoordinated concurrent membership updates produce split-brain forks where different network subsets install different keys for the same epoch number.

### 6.2 The V1 Group Coordinator (Admin) Model
To achieve deterministic ordering without the overhead of Paxos or Raft in V1:
- Each group designates an **Admin / Coordinator** (by default, the group creator).
- All membership actions (`JOIN`, `LEAVE`, `REMOVE`) must be submitted to or initiated by the Admin. The Admin also assigns each member's collision-free sender prefix at admission (§5.2).
- The Admin acts as the single committer:
  1. Validates the state transition against current group membership.
  2. Increments epoch $e \to e+1$.
  3. Generates fresh random $K_{e+1}$.
  4. Wraps $K_{e+1}$ for all active members.
  5. Computes `membership_hash` over the sorted `node_id:sender_prefix` entries (`docs/protocol.md` §4.3).
  6. Signs the `GROUP_UPDATE` payload using its long-term Ed25519 key (`docs/protocol.md` §4.3).
  7. Injects the signed update into the epidemic gossip network.
- **Node Validation Rules:** Receiving nodes reject any `GROUP_UPDATE` where:
  - The update signature does not verify against the **pinned** group Admin's public key (roster manifest, §5.5);
  - The `new_epoch` is not strictly $e_{\text{current}} + 1$ (gap ⇒ buffer + `STATE_REQUEST` resync, `docs/protocol.md` §6.2);
  - The receiver has already applied or processed the `update_id`.

### 6.3 Admin Failure & Compromise — Explicit V1 Limitations
The single-committer model buys linearizability by fiat; its costs are documented rather than hidden:
- **Admin unavailability (SPOF):** membership transitions stall while the Admin is unreachable; ordinary messaging continues on the current epoch. Admin handover/rotation is future work.
- **Admin compromise = total group break:** the attacker can sign arbitrary membership and wrap $K_{e+1}$ for arbitrary recipients. V1 mitigation: detect impact via telemetry, dissolve the group, and recreate it out of band. (Contrast with member compromise, §9, which epoch rotation does contain.)
- **Malicious double-signing (fork detection):** if a node ever holds two valid Admin-signed updates with the same $(\text{group\_id}, \text{new\_epoch})$ but different `update_id`/content, it logs `ADMIN_DOUBLE_SIGN` with both artifacts as evidence, keeps the first-installed state (deterministic, no flapping), and exposes the event as a telemetry metric for the partition/malicious-admin experiments.

---

## 7. Epidemic Gossip Engine

Nodes maintain a local peer table and propagate protocol updates using a bounded epidemic gossip protocol over the simulated data-plane:

1. **Update Tracking & De-duplication:**
   - Every gossip message carries the deterministic `update_id` of `docs/protocol.md` §4.3 (domain-separated `SHA256` over `admin_id | group_id | new_epoch | signature`).
   - Nodes maintain a bounded LRU cache of `seen_update_ids` (persisted across restarts) plus a per-group ring-buffer **update log** of the last 256 valid updates.
   - If `update_id` has already been seen, the message is dropped immediately (after the double-sign check of §6.3).
2. **Fanout Dissemination:**
   - Upon receiving a valid, unseen `GROUP_UPDATE`, the node forwards it to $k$ randomly chosen connected peers (default fanout $k = 3$) from its known topology neighbors. Multi-hop spread proceeds edge-by-edge along the topology graph — the epidemic behavior under study.
3. **Anti-Entropy Resynchronization (the missing safety net):**
   - Push-only gossip cannot recover from restarts, late joins, or cache eviction — affected nodes would wedge at `ERR_EPOCH_GAP` forever.
   - Every $T_a$ (default 2s, jittered), nodes exchange `STATE_DIGEST` summaries with a random neighbor; mismatches trigger a `STATE_REQUEST`/`STATE_BUNDLE` pull of missing updates from the neighbor's update log, and the Admin republishes the current update on request (`docs/protocol.md` §6.2).
4. **Persistence & Restart:**
   - Epoch/membership/key material, replay windows, and the seen-set persist to a `0600` state directory; a restarted daemon resumes at its last epoch (never epoch 0) and backfills via (3) (`docs/protocol.md` §6.3).
5. **Transport Layer:**
   - Gossip and messaging run over **asynchronous TCP sockets** (`asyncio`) with 4-byte length-prefixed frames (1 MiB ceiling).
   - TCP handles stream framing, eliminates 1500-byte UDP MTU fragmentation for large key-wrap blocks, and provides socket-level backpressure. Connections open with a roster-verified `HELLO` frame (`docs/protocol.md` §10).

---

## 8. Node Inspection & Telemetry

Nodes expose an out-of-band JSON-RPC interface over Unix Domain Sockets:

```bash
gossip-sim node show <node_id> [--json]
```

### Inspectable State Attributes
- **Identity & Keys:** Node ID, Ed25519 public key, X25519 public key, certificate fingerprint, issuer, and validity window.
- **Network Status:** Namespace, per-link addresses (peer, interface, local/remote `/31` endpoints), listening port, active peer connections, connection uptime.
- **Group Memberships:** Group ID, current local epoch, member map (`node_id` → sender prefix), assigned role (Admin/Member), current epoch key fingerprint (`SHA256(K_epoch)[:8]`).
- **Telemetry Counters:** Messages sent, messages received, gossip messages propagated, duplicate updates dropped, signature verification failures, decryption failures, replay attempts detected, anti-entropy resync rounds, double-sign evidence events.
- **Security State:** Compromised flag, active attack modes, recent security events.

Raw secrets (private keys, epoch keys) are excluded by default; the `node.secrets --unsafe` debugging view exists but is hard-gated behind the daemon's `--unsafe-allow-secret-export` startup flag (`docs/protocol.md` §8).

---

## 9. Attack Engine & Adversary Simulation

The simulator includes an integrated **Attack Engine** operating across two distinct layers:

| Attack Mode | Layer | Mechanism | Expected Protocol Behavior |
|---|---|---|---|
| **Replay Attack** | Node / Network | Re-injects an old, captured `GROUP_UPDATE` or `GROUP_MSG` | Update rejected by `seen_update_ids` cache; data message rejected by sliding counter check |
| **Payload Tampering** | Network | Bit-flip in the ciphertext or signature in transit | GCM tag verification failure or Ed25519 signature verification failure; dropped |
| **Identity Forgery** | Node | Node injects update purporting to be from another node without private key | Ed25519 signature fails immediately; peer logged as malicious |
| **Malicious Gossip** | Node | Compromised node broadcasts conflicting epoch or malformed member list | Rejected due to invalid admin signature or invalid epoch progression |
| **Admin Double-Sign** | Node | Malicious Admin signs two different `GROUP_UPDATE`s for the same epoch | Both verify; first-installed state kept and `ADMIN_DOUBLE_SIGN` logged with both artifacts as evidence (detection, not prevention — §6.3) |
| **Gossip Suppression** | Node / Network | Malicious relay silently drops `GROUP_UPDATE` instead of forwarding | Anti-entropy digests heal the gap within one $T_a$ round (§7, item 3) |
| **Removed Member Attack** | Crypto | Removed member attempts to decrypt traffic in $e+1$ using $K_e$ | AES-GCM decryption failure (key mismatch) |
| **New Member Attack** | Crypto | New member in $e$ attempts to decrypt captured historical traffic from $e-1$ | Inability to unwrap historical keys (no historical wrap addressed to them; ephemeral erased best-effort) |
| **Node Compromise** | Control | Exports node private keys ($sk_{\text{ed}}, sk_{\text{x}}$) via `node.secrets` (daemon-gated `--unsafe-allow-secret-export`) | Demonstrates impact radius and immediate mitigation upon admin-triggered removal + rekey |
| **Network Partition** | Network | `ip link set down` on every link crossing the cut $(A, B)$ | Gossip halts across the partition boundary; state reconverges via anti-entropy once the links are healed |

---

## 10. Threat Model & V1 Limitations

### 10.1 Attacker Classes
| Attacker | Capabilities | Contained By / Out of Scope |
|---|---|---|
| **Passive network observer** | Reads all data-plane traffic | AEAD confidentiality of `GROUP_MSG`; traffic metadata (sizes, timing) is NOT hidden |
| **Active network attacker** | Drops, delays, replays, modifies, duplicates, reorders frames on any link | Replay: §7 windows/caches; tampering: GCM/Ed25519; reorder/delay: counters; drop/suppression: anti-entropy (§7, item 3) |
| **Malicious participant** | Legit member sending invalid or conflicting protocol messages | Non-Admin updates rejected via pinned Admin key; a *malicious Admin* is detected, not prevented (§6.3) |
| **Compromised participant** | Node's private keys + current epoch key exfiltrated | Impact radius = that member's groups/epochs; containment via removal + rekey. Admin compromise is a total break — see §6.3 |

### 10.2 Explicit Non-Goals and Honesty Statements
- This is an **experimental prototype**, not a production messenger; its properties are *experimental goals demonstrated under test*, not formal security proofs (cf. `Initial_IDEA.md` §16).
- The Admin model means **no membership availability under Admin failure** and **no security against a malicious Admin** — V1 detects forks (`ADMIN_DOUBLE_SIGN`); prevention requires threshold signing or a consensus protocol (future work).
- **Python cannot guarantee memory zeroization** — key erasure is best-effort (`bytearray` overwrite + reference drop) and documented as such wherever it matters.
- The UDS control plane is **unauthenticated** (single-host testbed) and `node.secrets` export exists for experiments behind a daemon-side gate. The testbed host is the trust boundary.
- `DIRECT_MSG` is an unsigned test channel outside the security model (its `HELLO` binding is spoofable by design; all `GROUP_*` artifacts are independently authenticated).
- Canonical encodings, nonce construction, and message schemas are frozen in `docs/protocol.md` (per `Initial_IDEA.md` §36) before implementation begins.

---

## 11. Repository Architecture

```text
gossip-encryption-sim/
├── pyproject.toml             # Project configuration & dependencies (single source of truth)
├── cli.py                     # Simulator CLI entrypoint (argparse)
├── crypto/
│   ├── __init__.py
│   ├── engine.py              # Cryptographic engine facade (OpenSSL/cryptography; PQC-ready)
│   ├── identity.py            # Ed25519 key management & domain-separated signatures
│   ├── key_agreement.py       # X25519 Diffie-Hellman & ephemeral AES-256-KW wrapping
│   ├── symmetric.py           # AES-256-GCM AEAD with (sender-prefix || counter) nonces
│   └── certificate.py         # Self-signed identity metadata & fingerprinting (display only)
├── simulator/
│   ├── __init__.py
│   ├── orchestrator.py        # Lifecycle manager, resource ledger, crash-safe teardown
│   ├── namespace.py           # netns + per-edge veth pairs + /31 link allocator
│   ├── topology.py            # NetworkX graph -> link plan; runtime link add/remove
│   ├── network_impairer.py    # tc/netem per link (loss, latency; partitions via link state)
│   └── attack_engine.py       # Attack injection coordinators
├── node/
│   ├── __init__.py
│   ├── daemon.py              # Main node async loop inside namespace
│   ├── state.py               # Node runtime state, peer table, group registries (persistent)
│   ├── gossip.py              # Rumor-mongering, seen cache, update log, anti-entropy
│   ├── messaging.py           # HELLO + direct/group/STATE_* data-plane handlers
│   ├── control_server.py      # Unix domain socket RPC server for CLI inspection
│   └── logger.py              # Structured JSONL event logger
├── experiments/
│   ├── __init__.py
│   ├── convergence.py         # Gossip propagation time vs network loss (seeded, N>=5)
│   ├── churn_resilience.py    # Throughput under rapid joins/leaves
│   ├── partition_recovery.py  # Time-to-reconverge after partition healing
│   ├── attack_metrics.py      # Detection rates for replay/tamper/double-sign attacks
│   └── plotter.py             # Matplotlib charts (mean +/- stdev)
├── docs/
│   └── protocol.md            # Canonical wire format and state machine specification
└── tests/
    ├── test_crypto.py         # Primitives, nonce/prefix rules, canonical encodings
    ├── test_gossip.py         # Seen cache, fanout, epoch transitions
    ├── test_group_state.py    # Membership machine, double-sign detection, grace keys
    ├── test_resync.py         # Anti-entropy recovery (restart/late join/epoch gap)
    ├── test_namespace.py      # netns + per-link isolation (root required)
    └── test_attacks.py        # Replay/tamper/key-exclusion defenses (root required)
```

---

## 12. Refined V1 Roadmap & Phasing

```text
+--------------------------------------------------------------------------+
| PHASE 1: Virtual Networking & Control Foundation                         |
|  - Root privileges / netns lifecycle / per-edge veth links / /31 alloc   |
|  - Topology-by-construction link plan (NetworkX -> link index)           |
|  - Crash-safe resource ledger + `gossip-sim destroy` teardown            |
|  - Out-of-band Unix Domain Socket IPC for node inspection                |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| PHASE 2: Cryptographic Engine                                            |
|  - Ed25519 signatures, X25519 key exchange, HKDF-SHA256                  |
|  - AES-256-GCM with (SenderPrefix || Counter) nonces                     |
|  - Ephemeral-static AES-256-KW key wrapping (HPKE-lite)                  |
|  - Canonical encoding rules + test vectors (docs/protocol.md §3.1)       |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| PHASE 3: Node Daemon & Direct Messaging                                  |
|  - Asyncio TCP server running inside netns (HELLO roster verification)   |
|  - Direct node-to-node messaging (ping/pong, text exchange)               |
|  - Structured JSONL logging pipeline                                     |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| PHASE 4: Group State, Epochs & Gossip Dissemination                      |
|  - Admin-coordinated group creation, join, leave, remove                 |
|  - Monotonic epoch transitions with fresh keys & prefix assignment       |
|  - Epidemic gossip router with LRU de-dup cache + update log             |
|  - Anti-entropy resync (STATE_DIGEST/REQUEST/BUNDLE) + persistence       |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| PHASE 5: Network Impairment & Attack Simulation                          |
|  - tc/netem per-link latency, loss, reorder; link-cut partitions         |
|  - Replay, tamper, forgery, double-sign, and node compromise drivers     |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| PHASE 6: Metrics, Automated Experiments & CLI Polish                     |
|  - Experiment harness: seeded runs, N>=5 repetitions, mean +/- stdev     |
|  - Convergence/detection metric definitions (PLAN.md Resolved Decision 6)|
|  - Pandas / Matplotlib plots for evaluation reports                      |
+--------------------------------------------------------------------------+
```
