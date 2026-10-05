# Implementation Plan: Gossip-Based Secure Group Messaging Simulator

## Goal Description
Build an end-to-end distributed systems and applied cryptography testbed where independent node processes run inside isolated Linux network namespaces (`netns`), interconnect over dedicated per-edge virtual Ethernet (`veth`) point-to-point links (one `/31` link per NetworkX edge), communicate via direct messaging and AES-256-GCM encrypted group messaging, propagate state updates and key rotations via epidemic gossip (with anti-entropy resynchronization), and evaluate resilience under kernel-level network degradation (`tc/netem`) and active adversarial attacks.

The plan incorporates key lessons learned from `../concord` (strict control/data plane isolation, domain-separated cryptographic signatures, length-prefixed framing, and orchestrator-distributed roster key pinning) while addressing the core distributed consensus landmines (Admin Coordinator model for monotonic epoch linearizability and admin-assigned collision-free multi-sender nonce partitioning).

---

## User Review Required

> [!IMPORTANT]
> **Linux Privileges (`sudo` / `CAP_NET_ADMIN`):**
> Creating network namespaces (`ip netns add`), creating/moving veth pairs (`ip link add/move veth...`), and applying `tc/netem` queuing disciplines require `CAP_NET_ADMIN` / `sudo`. The orchestrator and root-requiring tests must run with root privileges (or configured via `sudoers`); node daemons run unprivileged inside their namespaces. The CLI must run as the same user that owns `/tmp/gossip-sim/sockets/` (see Component 4).

> [!IMPORTANT]
> **Nonce Uniqueness Guarantee (not probability):**
> Nonces for `AES-256-GCM` are constructed as 96 bits: `4-byte sender prefix || 8-byte big-endian monotonic counter`, where the 4-byte prefix is **assigned by the group Admin** at admission, collision-checked against all current members' prefixes, and published in the signed `GROUP_UPDATE` member map. Uniqueness is guaranteed by the single-committer Admin. A bare `SHA256(sender_id)[:4]` prefix is only collision-free with probability $\approx n^2/2^{33}$ and would make the IV-partitioning claim false at scale — the counter is per-epoch and increments before each send (first message of an epoch carries counter `1`).

> [!IMPORTANT]
> **Group Admin Coordinator Model (with explicit V1 limitations):**
> To prevent split-brain epoch forks during epidemic gossip propagation, epoch transitions ($e \to e+1$) and fresh random key generation ($K_{e+1}$) are serialized exclusively by the designated group Admin. Accepted V1 consequences: the Admin is a single point of failure (membership changes stall while it is unreachable; messaging continues), an Admin compromise is a total break for that group (mitigation: dissolve and recreate the group), and malicious double-signing is detected and logged (`ADMIN_DOUBLE_SIGN`) rather than prevented. Admin handover/rotation is future work.

---

## Resolved Decisions

> [!NOTE]
> 1. **Transport Protocol:** Asynchronous TCP sockets (`asyncio`) for both direct messaging and gossip, with 4-byte length-prefixed framing and a 1 MiB frame ceiling — eliminates 1500-byte MTU fragmentation during wrapped key bundle broadcasts. Confirmed.
> 2. **Key Wrap Mechanism:** RFC 3394 `AES-256-KeyWrap` using pairwise secrets derived via `X25519` + `HKDF-SHA256` (PyCA `cryptography.hazmat.primitives.keywrap`). The `AES-GCM`-as-wrap alternative is dropped — exactly one wrap mechanism in V1.
> 3. **Topology Enforcement:** Per-edge `veth` links (topology by construction), rejecting the shared-bridge + `iptables -m physdev` design — the latter is silently inert without `br_netfilter`, leaks broadcast/ARP floods, and scales $O(n^2)$ in filter rules.
> 4. **Identity Pinning:** The orchestrator generates a roster manifest (`node_id` → Ed25519/X25519 public keys + fingerprints) at `init` and distributes it to every node's state directory before daemons start; nodes pin these keys and never rely on first-seen bootstrap (which is spoofable at group formation).
> 5. **Resynchronization:** Push-only rumor-mongering is insufficient (restarts, late joins, and LRU eviction wedge nodes at `ERR_EPOCH_GAP` forever). V1 adds periodic anti-entropy digest rounds (`STATE_DIGEST`/`STATE_REQUEST`) plus persistent node state across restarts.
> 6. **Experiment Rigor:** All benchmarks fix their RNG seeds (topology generation, fanout sampling), run $N \ge 5$ repetitions, and report mean ± stdev. "Convergence time" is defined as the interval from the Admin's commit timestamp to the moment $\ge 90\%$ (and separately $100\%$) of surviving members have installed $e+1$, measured on the shared host clock from JSONL events.

---

## Proposed Changes

```text
Gossip-Encryption-Sim/
├── pyproject.toml                         # Project configuration and dependencies (single source of truth)
├── cli.py                                 # Main CLI orchestrator (argparse)
├── crypto/
│   ├── __init__.py
│   ├── engine.py                          # Crypto-provider facade (algorithm abstraction, PQC-ready)
│   ├── identity.py                        # Ed25519 keypair generation, domain-separated sign/verify
│   ├── key_agreement.py                   # X25519 ECDH + HKDF-SHA256 + AES-256-KW ephemeral key wrap
│   ├── symmetric.py                       # AES-256-GCM with (sender-prefix || counter) nonces & AAD
│   └── certificate.py                     # Self-signed identity metadata & SHA256 fingerprints
├── simulator/
│   ├── __init__.py
│   ├── orchestrator.py                    # Lifecycle manager, resource ledger, crash-safe teardown
│   ├── namespace.py                       # Linux netns + per-edge veth pairs + /31 link allocator
│   ├── topology.py                        # NetworkX graph -> edge/link plan; runtime link add/remove
│   ├── network_impairer.py                # tc/netem per link (loss, latency, jitter) & link-cut partitions
│   └── attack_engine.py                   # Attack injection (replay, tamper, forgery, compromise)
├── node/
│   ├── __init__.py
│   ├── daemon.py                          # Asyncio daemon main loop running inside netns
│   ├── control_server.py                  # Out-of-band Unix Domain Socket JSON-RPC server
│   ├── state.py                           # Node state, peer registry, group epochs, keystore (persistent)
│   ├── messaging.py                       # Length-prefixed framing, HELLO + direct/group message handlers
│   ├── gossip.py                          # Rumor-mongering, seen LRU, update log, anti-entropy resync
│   └── logger.py                          # Structured JSONL event logger
├── experiments/
│   ├── __init__.py
│   ├── convergence.py                     # Benchmark: gossip convergence time vs network loss (seeded, N>=5)
│   ├── partition_recovery.py              # Benchmark: re-convergence time after partition healing
│   ├── churn_resilience.py                # Benchmark: throughput under rapid joins/leaves
│   ├── attack_metrics.py                  # Benchmark: detection rates for replay/tamper/double-sign
│   └── plotter.py                         # Generates matplotlib evaluation charts (mean +/- stdev)
├── docs/
│   └── protocol.md                        # Canonical wire format and state machine specification
└── tests/
    ├── test_crypto.py                     # Crypto primitives, nonce/prefix rules, canonical encodings
    ├── test_gossip.py                     # Seen cache, fanout, epoch transitions (mock sockets)
    ├── test_group_state.py                # Membership state machine, double-sign detection, grace keys
    ├── test_resync.py                     # Anti-entropy: restart/late-join/epoch-gap recovery
    ├── test_namespace.py                  # Integration: netns + per-link isolation (root required)
    └── test_attacks.py                    # Replay, tampering, key-exclusion defenses (root required)
```

---

### Component 1: Environment & Project Setup

#### [NEW] `pyproject.toml`
Single source of truth for dependencies (no parallel `requirements.txt` to drift; export one only for deployment). Dependencies: `cryptography` (PyCA/OpenSSL 3.x), `networkx` (graph topologies), `pandas` & `matplotlib` (experimental data analysis), `pytest` + `pytest-asyncio` (dev/test). Network setup uses standard `iproute2`/`tc`/`ip netns` CLI utilities via subprocess wrappers (`pyroute2` optional later).

```toml
[project]
name = "gossip-encryption-sim"
version = "0.1.0"
description = "Gossip-Based Secure Group Messaging Simulator in Linux Namespaces"
dependencies = [
    "cryptography>=42.0.0",
    "networkx>=3.2",
    "pandas>=2.2.0",
    "matplotlib>=3.8.0",
]
requires-python = ">=3.10"

[dependency-groups]
dev = ["pytest>=8.0.0", "pytest-asyncio>=0.23.0"]
```

---

### Component 2: Cryptographic Engine (`crypto/`)

#### [NEW] `crypto/engine.py`
Thin crypto-provider facade (algorithm registry) so future PQC primitives can be introduced without touching the gossip layer — as required by `Initial_IDEA.md` §32.

#### [NEW] `crypto/identity.py`
Ed25519 key generation, serialization, and **explicitly parameterized** domain-separated signing/verification. The signed payload for group updates is exactly one construction (`docs/protocol.md` §4.3): `"gossip-sim-v1:group-update:v1|" || SHA256(CanonicalString)`.

```python
class IdentityKeypair:
    def __init__(self, private_key=None):
        self.private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def sign(self, message: bytes, domain: str) -> bytes:
        return self.private_key.sign(domain.encode() + message)

    @staticmethod
    def verify(public_bytes: bytes, signature: bytes, message: bytes, domain: str) -> bool:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        try:
            pub.verify(signature, domain.encode() + message)
            return True
        except Exception:
            return False
```
The `domain` parameter is mandatory (no default that silently signs under the wrong purpose tag); callers pass `"gossip-sim-v1:group-update:v1|"`, `"gossip-sim-v1:hello:v1|"`, etc.

#### [NEW] `crypto/symmetric.py`
AES-256-GCM with the strict deterministic nonce structure (`docs/protocol.md` §4.2):
$$\text{Nonce (12B)} = \text{sender\_prefix (4B, admin-assigned)} \parallel \text{uint64\_BE(counter)}$$
Binds AAD: `"v1|" || group_id || "|" || epoch || "|" || sender_id || "|" || counter` (identifiers validated per `docs/protocol.md` §3.1 at the trust boundary).

```python
class SymmetricGroupCipher:
    @staticmethod
    def build_nonce(sender_prefix: bytes, counter: int) -> bytes:
        assert len(sender_prefix) == 4
        return sender_prefix + struct.pack(">Q", counter)

    @staticmethod
    def build_aad(group_id: str, epoch: int, sender_id: str, counter: int) -> bytes:
        return f"v1|{group_id}|{epoch}|{sender_id}|{counter}".encode()

    @classmethod
    def encrypt(cls, group_key: bytes, plaintext: bytes, sender_prefix: bytes,
                group_id: str, epoch: int, sender_id: str, counter: int) -> tuple[bytes, bytes]:
        nonce = cls.build_nonce(sender_prefix, counter)
        aad = cls.build_aad(group_id, epoch, sender_id, counter)
        return nonce, AESGCM(group_key).encrypt(nonce, plaintext, aad)

    @classmethod
    def decrypt(cls, group_key: bytes, nonce: bytes, ciphertext: bytes, sender_prefix: bytes,
                group_id: str, epoch: int, sender_id: str, counter: int) -> bytes:
        if nonce != cls.build_nonce(sender_prefix, counter):
            raise ValueError("Nonce does not match sender prefix and counter")
        aad = cls.build_aad(group_id, epoch, sender_id, counter)
        return AESGCM(group_key).decrypt(nonce, ciphertext, aad)
```
The nonce prefix is taken from the **pinned** `sender_prefix` of the epoch's member map — never from the message envelope alone.

#### [NEW] `crypto/key_agreement.py`
X25519 Diffie-Hellman, HKDF-SHA256 derivation, and Ephemeral-Static key wrapping (HPKE-lite) with RFC 3394 `AES-256-KW` (PyCA `cryptography.hazmat.primitives.keywrap`) — exactly as specified in `docs/protocol.md` §5, including the version-tagged HKDF info string `gossip-sim-v1:gossip-wrap:v1|{group_id}|{epoch}`.

#### [NEW] `crypto/certificate.py`
Self-signed identity metadata (`node_id` ↔ public keys) and SHA256 fingerprints for display — a metadata layer only. The trust anchor is the orchestrator's `roster.json` manifest (`docs/protocol.md` §10); no PKI or chain validation in V1.

---

### Component 3: Linux Namespaces & Virtual Network Subsystem (`simulator/`)

#### [NEW] `simulator/namespace.py`
Creation and destruction of Linux network namespaces and **per-edge veth links** (topology by construction — Resolved Decision 3):
- For each node: `ip netns add netns-{node_id}`; the daemon is launched via `ip netns exec`.
- For each undirected edge $(u, v) \in E(G)$ with link index $n$:
  - `ip link add vlk{n}a type veth peer name vlk{n}b` (IFNAMSIZ-safe names ≤ 15 chars — node-name-based interface names like `veth-alice-charlie` silently fail to create).
  - Move `vlk{n}a` into `netns-{u}`, `vlk{n}b` into `netns-{v}`.
  - Assign the link's `/31` (RFC 3021) from the deterministic allocator carving `10.200.0.0/16` into `/31`s in edge-index order; sorted node IDs take `.0` / `.1`.
  - Set both ends UP.
- No bridge, no forwarding, no iptables: non-adjacent nodes have **no L3 path at all**, so adjacency filtering is unnecessary — and cannot silently fail (the `br_netfilter`-less no-op trap of the shared-bridge design).

#### [NEW] `simulator/topology.py`
Compiles the NetworkX graph into a link plan and manages runtime topology changes:
- Deterministic edge ordering (sorted node-ID pairs) → link index → interface names + `/31` subnets.
- `link add|remove <u> <v>` creates/destroys the veth pair at runtime and nudges peer tables over UDS.
- Partition helper: computes the edge cut between node subsets $A$ and $B$ and hands it to the impairer.

#### [NEW] `simulator/network_impairer.py`
Per-link Traffic Control (`tc netem`) on the veth ends of a specific edge (so "lossy alice–bob link" is expressible without collateral damage to alice's other links):
- Loss (`loss <pct>%`), latency/jitter (`delay <ms>ms <jitter>ms distribution normal`), reorder/duplicate.
- `--node` variant applies the same qdisc to every incident link end of that node.
- Link failure / partitions: `ip link set vlk{n}a down` for every edge crossing the cut; link state is recorded in the orchestrator's resource ledger for `heal`/`destroy`.

---

### Component 4: Node Daemon & Out-of-Band Control Plane (`node/`)

#### [NEW] `node/control_server.py`
Local Unix Domain Socket JSON-RPC server at `/tmp/gossip-sim/sockets/{node_id}.sock`.
- Supports methods: `node.inspect`, `node.send_direct`, `node.group_create`, `node.group_join`, `node.group_leave`, `node.group_send`, `node.inject_attack`, `node.secrets` (unsafe-gated).
- Bypasses virtual network degradation so node status can always be queried by the CLI.
- **Privileges:** the orchestrator creates the socket directory `0750` and each socket `0660`, owned by the invoking user (`SUDO_UID` when run under sudo). The manual-verification steps that mix root and non-root invocations must run as this owner or fail with `EACCES`.
- **Unsafe gating:** `node.secrets` (private/raw key export for compromise experiments) is refused unless the *daemon* was started with `--unsafe-allow-secret-export` — a CLI-side flag alone is insufficient.

#### [NEW] `node/messaging.py`
4-byte length-prefixed TCP wire framing (1 MiB frame ceiling):
- Encodes/decodes canonical JSON frames: `HELLO` (roster-verified identity binding), `DIRECT_MSG`, `GROUP_MSG`, `GROUP_UPDATE`, `STATE_DIGEST`, `STATE_REQUEST`, `STATE_BUNDLE` (`docs/protocol.md` §3–§6).
- Applies the `GROUP_MSG` validation pipeline (`docs/protocol.md` §7.3): epoch/grace, membership, pinned sender prefix, sliding window, AEAD.

#### [NEW] `node/daemon.py`
The process executed inside the namespace (`ip netns exec netns-alice python3 -m node.daemon --id alice --port 9000`):
- Loads identity keypairs + the pinned `roster.json` manifest (`docs/protocol.md` §10).
- Recovers persisted state (epoch, keys, replay windows, seen-set) **before** networking starts — never boots at epoch 0 when persistence exists.
- Starts the out-of-band UDS control server and the in-band TCP server (bound on all per-link addresses).
- Maintains peer connections, anti-entropy rounds, state, and structured JSONL logs.

---

### Component 5: Group State Machine & Gossip Engine (`node/`)

#### [NEW] `node/state.py`
Group metadata and durable state (persisted to a `0600` state directory, reloaded at daemon boot):
- Group ID, Admin ID, Current Epoch $e$, Member map (`node_id` → sender prefix), Current Group Key $K_e$.
- Grace key window: exactly $K_e$ and $K_{e-1}$ retained ($K_{e-2}$ dropped at install time) for in-flight messages during transitions. Best-effort erasure only — Python cannot guarantee zeroization (documented, not claimed).
- Sliding replay window (64-bit bitmask + max counter) per (group, epoch, sender).
- Seen-ID set + per-group update log ring buffer (last 256 valid updates) for resync serving.

#### [NEW] `node/gossip.py`
Epidemic gossip router + anti-entropy:
- `seen_update_ids` LRU cache (10,000 entries), persisted across restarts.
- Fanout router: selects $\min(k, |\text{peers}|)$ random neighbors to forward valid updates.
- Anti-entropy loop (default every 2 s ±50 % jitter): `STATE_DIGEST` → diff → `STATE_REQUEST` → `STATE_BUNDLE`, replayed through the verification pipeline (`docs/protocol.md` §6.2).
- Group state update verification pipeline:
  1. Check if `update_id` already seen → run the double-sign check (below) then drop.
  2. Verify Ed25519 signature against the **pinned** Admin key (roster manifest) → reject if invalid.
  3. Validate epoch transition ($e_{\text{new}} == e_{\text{local}} + 1$); on gap → buffer + `STATE_REQUEST`; on stale → drop.
  4. Unwrap new epoch key $K_{e+1}$ using the local X25519 private key (AES-256-KW integrity-checked).
  5. Install $K_{e+1}$ (rotate the grace window), update the member map, advance local epoch, persist.
  6. Forward the update to $k$ random peers.
- **Double-sign detection:** two valid Admin-signed updates for the same $(\text{group\_id}, \text{new\_epoch})$ with different content → keep the first-installed state, log `ADMIN_DOUBLE_SIGN` with both artifacts as evidence, bump `double_sign_detected`.

---

### Component 6: Attack Simulation Engine (`simulator/attack_engine.py`)

#### [NEW] `simulator/attack_engine.py`
Orchestrates active and passive attacks:
1. **Network-Level Attacks:** drives `tc netem` per link and link-state cuts via `simulator/network_impairer.py` (loss, latency, reorder, duplicate, down/up).
2. **Replay Attack:** captures an old `GROUP_UPDATE` or `GROUP_MSG` and re-injects it; verifies the target logs `REPLAY_DETECTED` / `ERR_REPLAY`.
3. **Payload Tamper Attack:** intercepts an outgoing frame and flips bits in ciphertext or signature; verifies GCM authentication failure or Ed25519 failure.
4. **Identity Forgery / Malicious Gossip:** injects updates under another node's ID or with malformed membership; verifies `ERR_SIG_INVALID` / `ERR_UNAUTHORIZED`.
5. **Admin Double-Sign:** drives a hostile-Admin scenario producing two conflicting updates for one epoch; verifies `ADMIN_DOUBLE_SIGN` detection (Component 5).
6. **Node Compromise:** extracts private keys over UDS (`node.secrets`, honored only on daemons started with `--unsafe-allow-secret-export`), demonstrating impact radius and mitigation upon admin-triggered removal + rekey.

---

### Component 7: CLI Orchestrator (`cli.py`)

#### [NEW] `cli.py`
Unified command-line interface using `argparse` (one canonical command set, subcommand style throughout):
- **Simulator management:** `gossip-sim init --nodes alice,bob,charlie,dave --topology linear` (or `--nodes 5` for auto-named `node-1..5`), `gossip-sim start`, `gossip-sim stop`, `gossip-sim status`, `gossip-sim destroy` (idempotent teardown of netns/links/qdiscs/sockets from the resource ledger)
- **Topology management:** `gossip-sim link add <u> <v>`, `gossip-sim link remove <u> <v>`
- **Direct Messaging:** `gossip-sim send <from> <to> "<message>"`
- **Group Management:** `gossip-sim group create <admin> <group_id>`, `gossip-sim group join <admin> <group_id> <node>`, `gossip-sim group leave <admin> <group_id> <node>`, `gossip-sim group send <from> <group_id> "<message>"`
- **Node Inspection:** `gossip-sim node list`, `gossip-sim node show <node_id> [--json]`, `gossip-sim node secrets <node_id> --unsafe` (daemon-gated)
- **Network Impairment (per-link):** `gossip-sim network loss --link alice,bob --rate 10` (or `--node <node>` for all incident links), `gossip-sim network latency --link alice,bob --delay 100ms --jitter 20ms`, `gossip-sim network partition --group-a alice,bob --group-b charlie,dave`, `gossip-sim network heal`
- **Attack Injection:** `gossip-sim attack replay --target <node>`, `gossip-sim attack tamper --from <node> --to <target>`, `gossip-sim attack forge --as <node> --to <target>`, `gossip-sim attack double-sign --admin <node> --group <group_id>`, `gossip-sim attack compromise <node>`

---

### Component 8: Automated Experiments & Visualization (`experiments/`)

#### [NEW] `experiments/convergence.py`
Automated benchmark sweeps:
- Evaluates gossip convergence latency across topologies (linear, ring, random) under varying per-link packet loss (0%, 5%, 10%, 20%).
- Metric definitions (Resolved Decision 6): convergence time = Admin commit timestamp → $\ge 90\%$ (and separately $100\%$) of surviving members installed $e+1$, measured from JSONL events on the shared host clock.
- Rigor: fixed RNG seeds (networkx graph generation, fanout sampling), $N \ge 5$ repetitions per data point, mean ± stdev written to `experiments/data/convergence_results.json`.

#### [NEW] `experiments/partition_recovery.py`
Re-convergence time after healing a cut $(A, B)$ (link-state partition), same rigor profile; separately reports the anti-entropy-only recovery path (gossip-suppression scenario).

#### [NEW] `experiments/churn_resilience.py`
Throughput and epoch-transition latency under rapid join/leave churn.

#### [NEW] `experiments/attack_metrics.py`
Detection rates and time-to-detect for replay, tampering, forgery, and admin double-sign scenarios (counters sourced from node JSONL telemetry).

#### [NEW] `experiments/plotter.py`
Loads JSON experiment logs and generates publication-quality Matplotlib plots (mean ± stdev error bars):
- Convergence time vs. packet loss percentage.
- Duplicate gossip overhead vs. fanout factor $k$.
- Detection latency by attack type.

---

## Verification Plan

### Automated Tests
1. **Crypto Unit Tests (zero-privilege):**
   ```bash
   pytest tests/test_crypto.py -v
   ```
   - Ed25519 sign/verify with rejection of altered payloads; mandatory domain-separation enforcement.
   - AES-256-GCM nonce construction and counter sequencing; two senders with equal counters yield distinct nonces **by assigned prefix**, and the salted collision-retry path is exercised with forced candidate collisions.
   - Canonical encoding vectors: `update_id`, AAD, HKDF info, and `CanonicalJSON` (key-order/whitespace independence) match `docs/protocol.md` §3.1/§4.3.
   - X25519 ECDH + HKDF + AES-256-KW wrap/unwrap round-trip; wrapped-key tamper → `ERR_KEY_UNWRAP`.
2. **Group State Machine Tests (zero-privilege):**
   ```bash
   pytest tests/test_group_state.py -v
   ```
   - Epoch advancement; rejection of stale/gap epochs; grace-key window holds exactly $K_e, K_{e-1}$.
   - `GROUP_MSG` validation pipeline: non-member sender, prefix mismatch, replay window.
   - Admin double-sign detection: conflicting updates for one epoch → first-installed kept + `ADMIN_DOUBLE_SIGN` evidence.
3. **Gossip & Resync Tests (mock sockets):**
   ```bash
   pytest tests/test_gossip.py tests/test_resync.py -v
   ```
   - LRU de-dup cache + persisted seen-set; fanout selection.
   - Anti-entropy: restart recovery, late-join recovery, epoch-gap backfill via `STATE_REQUEST`/`STATE_BUNDLE`, suppression healing within one $T_a$.
4. **End-to-End Namespace & Topology Tests (root required):**
   ```bash
   sudo pytest tests/test_namespace.py -v
   ```
   - Creates 3 namespaces + per-edge links; verifies reachability **only between adjacent pairs** (non-adjacent nodes have no path by construction).
   - Teardown removes every netns/link even after an induced mid-test failure (resource ledger check).
5. **Attack Defense Verification (root required):**
   ```bash
   sudo pytest tests/test_attacks.py -v
   ```
   - Replay detection on duplicate updates/messages; ciphertext tampering → authentication failure logged.
   - Forgery → `ERR_SIG_INVALID`; removed-member message under stale epoch key → dropped after rotation.

### Manual Verification
Run all commands as the invoking user (the UDS socket owner); network-setup/teardown commands additionally need `sudo` (Component 4 privileges note).
1. Initialize a 4-node linear cluster:
   ```bash
   sudo python3 cli.py init --nodes alice,bob,charlie,dave --topology linear
   sudo python3 cli.py start
   python3 cli.py node list
   ```
2. Verify node inspection (per-link addresses + pinned roster visible):
   ```bash
   python3 cli.py node show alice
   ```
3. Test direct messaging and topology-by-construction:
   ```bash
   python3 cli.py send alice bob "Hello Bob"   # succeeds (adjacent)
   python3 cli.py send alice charlie "Hi"      # fails: no link exists by construction
   ```
4. Form an encrypted group and test messaging:
   ```bash
   python3 cli.py group create alice security-team
   python3 cli.py group join alice security-team bob
   python3 cli.py group join alice security-team charlie
   python3 cli.py group send alice security-team "Top secret payload"
   ```
5. Test key rotation and forward secrecy:
   ```bash
   python3 cli.py group leave alice security-team charlie
   python3 cli.py group send alice security-team "Charlie should not see this"
   # Inspect charlie: verify decryption failure counter incremented
   python3 cli.py node show charlie
   ```
6. Test partition, healing, and idempotent teardown:
   ```bash
   sudo python3 cli.py network partition --group-a alice,bob --group-b charlie,dave
   # Verify partition isolation, then heal and let anti-entropy reconverge:
   sudo python3 cli.py network heal
   sudo python3 cli.py destroy
   ```
