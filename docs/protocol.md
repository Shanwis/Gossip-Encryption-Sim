# Gossip-Based Secure Group Messaging: Protocol Specification (V1)

> **Document Version:** 1.0.0  
> **Status:** Draft / Normative Specification  
> **Applies to:** Gossip-Based Secure Group Messaging Simulator  

---

## 1. Overview & Protocol Roles

The protocol defines communication across two distinct planes:
1. **Data Plane (In-Band):** Transports direct messages, encrypted group messages, and gossip updates over simulated virtual networks (TCP/IP inside Linux network namespaces).
2. **Control Plane (Out-of-Band):** Transports inspection queries, configuration updates, and attack injection commands over local Unix Domain Sockets (`UDS`).

### 1.1 Node Roles
- **Participant (Member):** An active node belonging to a group possessing the current epoch's group key.
- **Group Admin (Coordinator):** The designated committer of the group (default: group creator). The Admin is the sole authority permitted to serialize membership changes, generate new epoch keys, wrap keys for members, and sign `GROUP_UPDATE` messages.
- **Adversary (Simulated):** A node or network hook executing replay, tampering, packet dropping, or spoofing.

---

## 2. Cryptographic Parameters & Constants

| Parameter | Specification | Value / Algorithm |
|---|---|---|
| Signature Scheme | RFC 8032 | `Ed25519` (256-bit public key, 512-bit signature) |
| Key Agreement | RFC 7748 | `X25519` (256-bit public key, 256-bit shared secret) |
| Group Cipher | NIST SP 800-38D | `AES-256-GCM` (256-bit key, 96-bit IV, 128-bit authentication tag) |
| Key Derivation | RFC 5869 | `HKDF-SHA256` |
| Key Wrapping | RFC 3394 | `AES-256-KW` (sole key-wrap mechanism in V1; the AES-GCM alternative is dropped to avoid implementer ambiguity) |
| Hash Function | FIPS 180-4 | `SHA-256` (32 bytes) |
| Sender Prefix | 32-bit unsigned | Admin-assigned, collision-checked per (group, member) — see §4.2 |
| Protocol Version | Integer | `1` |
| Maximum Group Size | Configurable | `32` (recommended for V1) |
| Maximum Frame Size | 4-byte length prefix | `1 MiB` payload ceiling (larger frames are a protocol error) |

---

## 3. Data Plane Wire Framing

Data Plane packets over TCP are length-prefixed frames:
```text
+------------------------+---------------------------------------+
|  Length (4 bytes, BE)  |      JSON Payload (UTF-8 encoded)     |
+------------------------+---------------------------------------+
```
- **Length:** 32-bit unsigned integer (big-endian) denoting the exact byte length of the trailing payload. Frames larger than 1 MiB are a protocol error and the connection is dropped.
- **Payload:** UTF-8 canonical JSON string. Binary values (keys, signatures, nonces, ciphertexts) MUST be standard-alphabet, padded base64.

### 3.1 Canonical Encoding Rules
All strings that enter hashes, KDF `info` contexts, AAD, or signatures are built with unambiguous, version-tagged encodings:
1. **Identifier charset:** `node_id`, `group_id`, and `sender_id` MUST match `^[A-Za-z0-9._-]{1,64}$`. This makes `|`-delimited concatenations collision-free (no field can contain `|`), removing the classic `"ab"| "c"` vs `"a"| "bc"` ambiguity from `update_id`, AAD, and HKDF info strings.
2. **Preimage form:** every hashed/derived string is `"<scheme>:<purpose>:v<version>|" || field1 || "|" || field2 ...` with integers as decimal without leading zeros.
3. **CanonicalJSON(X):** UTF-8 encoded; object keys sorted byte-lexicographically; separators `,` and `:` with no whitespace; integers only (no floats); strings escaped minimally per RFC 8259. (A restricted RFC 8785 JCS profile.)

---

## 4. Message Schemas

### 4.1 Direct Node-to-Node Message (`DIRECT_MSG`)
Used for out-of-group point-to-point communication and connectivity testing.

```json
{
  "version": 1,
  "type": "DIRECT_MSG",
  "msg_id": "dmsg_4f89a2bc17",
  "sender_id": "alice",
  "recipient_id": "bob",
  "timestamp": 1728123412.105,
  "payload": "Hello Bob, are you reachable?"
}
```

---

### 4.2 Encrypted Group Message (`GROUP_MSG`)
Carries group payload encrypted under the group key for a specific epoch.

```json
{
  "version": 1,
  "type": "GROUP_MSG",
  "msg_id": "gmsg_90e81c72a1",
  "group_id": "quantum-team",
  "epoch": 7,
  "sender_id": "alice",
  "counter": 14,
  "nonce": "N3d4R3g4U1pMQUFBQUFBQQ==",
  "ciphertext": "k8P+...base64_ciphertext_and_tag..."
}
```

#### Nonce Layout (96 bits / 12 bytes):
$$\text{Nonce} = \underbrace{\text{Sender Prefix (4 bytes)}}_{\text{Admin-assigned uint32 BE, unique per (group, member)}} \parallel \underbrace{\text{Monotonic Counter (8 bytes)}}_{\text{uint64 Big-Endian, strictly increasing per epoch}}$$

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Sender Prefix (32 bits, admin-assigned)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                Monotonic Message Counter (64 bits)            +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Sender Prefix Assignment (uniqueness GUARANTEED, not probabilistic):**
1. On member admission, the Admin derives a candidate prefix `SHA256("gossip-sim-v1:sender-prefix:v1|" || group_id || sender_id)[0:4]`.
2. The Admin checks the candidate against every current member's prefix. On collision, it re-derives with an appended salt counter (`... || "|" || salt`, `salt = 1, 2, ...`) until unique.
3. The Admin publishes `node_id → sender_prefix` (hex) in the signed `GROUP_UPDATE` member map; receivers MUST reject a `GROUP_MSG` whose sender prefix does not match the pinned member map (§7.3).

A bare 32-bit hash prefix is collision-free only with probability $\approx n^2/2^{33}$ (≈$1.2 \times 10^{-6}$ at 100 senders); two colliding senders with overlapping counters would reuse GCM IVs under the same key — catastrophic for AES-GCM. Assignment by the single-committer Admin converts this probability into a guarantee.

**Counter Discipline:** one monotonic counter per (group, epoch), incremented before every send; the first message of an epoch carries counter `1`. On counter exhaustion ($2^{64}$) the sender MUST request a rekey rather than wrap around.

#### Associated Authenticated Data (AAD):
The unencrypted envelope fields are cryptographically bound to the GCM tag. The AAD string MUST be constructed as:
$$\text{AAD} = \text{"v1|"} \parallel \text{group\_id} \parallel \text{"|"} \parallel \text{epoch} \parallel \text{"|"} \parallel \text{sender\_id} \parallel \text{"|"} \parallel \text{counter}$$
Example AAD: `"v1|quantum-team|7|alice|14"` (per §3.1 identifier charset restrictions make this `|`-concatenation unambiguous).

---

### 4.3 Group State Update (`GROUP_UPDATE`)
Disseminated via epidemic gossip whenever membership or epoch keys transition.

```json
{
  "version": 1,
  "type": "GROUP_UPDATE",
  "update_id": "6a2f7c01b94d...",
  "group_id": "quantum-team",
  "prev_epoch": 6,
  "new_epoch": 7,
  "action": "REMOVE_MEMBER",
  "target_member": "charlie",
  "members": {"alice": "9f2c11a0", "bob": "3b7e44c1", "dave": "77aa02de"},
  "membership_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "admin_id": "alice",
  "ephemeral_pubkey": "base64_x25519_ephemeral_public_key",
  "encrypted_keys": {
    "bob": "base64_wrapped_key_for_bob",
    "dave": "base64_wrapped_key_for_dave"
  },
  "signature": "base64_ed25519_signature_by_admin"
}
```

- `members` maps each member `node_id` to its admin-assigned **sender prefix** (hex, §4.2); the map is the authoritative nonce-prefix source for the epoch.
- `membership_hash = SHA256("gossip-sim-v1:membership:v1|" || "|".join(sorted(f"{node_id}:{prefix}" for node_id, prefix in members.items())))`.
- `encrypted_keys` carries one `AES-256-KW` blob per member excluding the Admin (who holds $K_{e+1}$ directly).

#### update_id:
$$\text{update\_id} = \text{SHA256}(\text{"gossip-sim-v1:update-id:v1|"} \parallel \text{admin\_id} \parallel \text{"|"} \parallel \text{group\_id} \parallel \text{"|"} \parallel \text{new\_epoch} \parallel \text{"|"} \parallel \text{base64(signature)})$$
(hex-encoded). Domain-separated and delimiter-safe per §3.1 — distinct updates cannot collide on the preimage.

#### Signature Scope:
The Admin's signature covers a version-tagged digest of the canonical serialization of all update fields **excluding the `signature` field itself**. Exactly one construction is legal (no alternatives):
$$\text{CanonicalString} = \text{CanonicalJSON}(\text{all fields except "signature"}) \quad (\text{per §3.1})$$
$$\text{SignedPayload} = \text{"gossip-sim-v1:group-update:v1|"} \parallel \text{SHA256}(\text{CanonicalString})$$
$$\text{Signature} = \text{Ed25519\_Sign}(sk_{\text{admin}}, \text{SignedPayload})$$

---

## 5. Ephemeral Key Wrapping Algorithm (HPKE-lite)

When transitioning to epoch $e+1$, the Group Admin executes the following procedure:

### 5.1 Admin Key Generation & Wrap Procedure
1. Sample a fresh 256-bit symmetric group key:
   $$K_{e+1} \leftarrow \text{CSPRNG}(32\text{ bytes})$$
2. Generate an ephemeral X25519 keypair:
   $$(sk_{\text{eph}}, pk_{\text{eph}}) \leftarrow \text{X25519\_Keygen}()$$
3. For each active member $M \in \text{members}$:
   - If $M == \text{admin\_id}$, the admin directly saves $K_{e+1}$ in its local keystore.
   - Otherwise, fetch member $M$'s pinned long-term X25519 public key $pk_{M}$ (roster manifest — see §10).
   - Compute the Diffie-Hellman shared secret:
     $$SS_M = \text{X25519}(sk_{\text{eph}}, pk_{M})$$
   - Derive the member's key-encryption key ($\text{KEK}_M$):
     $$\text{KEK}_M = \text{HKDF-Expand}(\text{PRK}=\text{HKDF-Extract}(\text{salt}=\emptyset, \text{IKM}=SS_M), \text{info}=\text{"gossip-sim-v1:gossip-wrap:v1|"} \parallel \text{group\_id} \parallel \text{"|" } \parallel (e+1), \text{len}=32)$$
   - Wrap $K_{e+1}$ (RFC 3394 `AES-256-KW` — the sole wrap mechanism in V1):
     $$\text{EncryptedKey}_M = \text{AES-256-KW}(\text{KEK}_M, K_{e+1})$$
4. Best-effort erasure of $sk_{\text{eph}}$ (overwrite a `bytearray`, drop references). *Honest caveat: CPython cannot guarantee memory zeroization; this is a documented limitation of the prototype, not a claim.*

### 5.2 Recipient Key Unwrap Procedure
Upon receiving a verified `GROUP_UPDATE`:
1. Check if recipient node ID $M$ is present in `members` and `encrypted_keys`.
2. Extract the ephemeral public key $pk_{\text{eph}}$ and $\text{EncryptedKey}_M$.
3. Compute the shared secret using recipient's private key $sk_M$:
   $$SS_M = \text{X25519}(sk_M, pk_{\text{eph}})$$
4. Derive identical $\text{KEK}_M$ via HKDF-Expand with the same context string.
5. Unwrap the key (AES-KW provides its own integrity check; failure ⇒ `ERR_KEY_UNWRAP`):
   $$K_{e+1} = \text{AES-256-KW-Unwrap}(\text{KEK}_M, \text{EncryptedKey}_M)$$
6. Install $K_{e+1}$ into the local active keystore for `group_id` at epoch $e+1$, retaining $K_{e-1}$ as a one-epoch grace key and dropping $K_{e-2}$ (sliding window of at most two epoch keys — see §7.3).
7. Initialize the local sending counter for epoch $e+1$ so that the first outgoing message carries counter `1`.

---

## 6. Epidemic Gossip Engine & State Transitions

### 6.1 Bounded Rumor-Mongering Algorithm
- **Fanout ($k$):** Default $k = 3$.
- **Update Log:** each node retains the last 256 valid `GROUP_UPDATE`s per group in a ring buffer (serves resync requests, §6.2).
- **Seen Cache:** each node maintains a fixed-size LRU buffer of `seen_update_ids` (capacity: 10,000 IDs), persisted across restarts (§6.3).
- When node $u$ receives a `GROUP_UPDATE` $U$:
  1. If $U.\text{update\_id} \in \text{seen\_update\_ids}$, drop immediately (**DUPLICATE**) — after running the double-sign check (§7.4).
  2. Verify the Ed25519 signature against the **pinned** admin public key from the roster manifest (§10); failure ⇒ drop (**BAD_SIGNATURE** / `ERR_SIG_INVALID`, `ERR_UNAUTHORIZED`).
  3. If $U.\text{new\_epoch} \le \text{local\_epoch}[U.\text{group\_id}]$, drop (**STALE_EPOCH**).
  4. If $U.\text{new\_epoch} > \text{local\_epoch}[U.\text{group\_id}] + 1$, buffer temporarily (**FUTURE_EPOCH_GAP**) and issue `STATE_REQUEST` (§6.2).
  5. Add $U.\text{update\_id}$ to $\text{seen\_update\_ids}$ and to the update log.
  6. Apply state transition and install new group key (§5.2).
  7. Select $\min(k, |\text{connected\_peers} \setminus \{\text{sender}\}|)$ random peers and forward $U$.

### 6.2 Anti-Entropy Resynchronization (`STATE_DIGEST` / `STATE_REQUEST` / `STATE_BUNDLE`)
Push-only rumor-mongering cannot recover from node restarts, late joins, or `seen_update_ids` eviction — affected nodes would wedge permanently at `ERR_EPOCH_GAP`. V1 therefore adds periodic pull-based anti-entropy:
- Every $T_a$ (default 2 s, ±50 % jitter), a node sends `STATE_DIGEST` to one random neighbor:
  ```json
  { "version": 1, "type": "STATE_DIGEST", "sender_id": "alice",
    "groups": { "quantum-team": { "epoch": 7, "membership_hash": "…", "latest_update_id": "…" } } }
  ```
- The neighbor diffs digests; for every group where its epoch exceeds the sender's (or `membership_hash` disagrees at equal epochs), it replies `STATE_REQUEST`:
  ```json
  { "version": 1, "type": "STATE_REQUEST", "req_id": "req_…", "sender_id": "bob",
    "group_id": "quantum-team", "from_epoch": 6, "known_update_ids": ["…"] }
  ```
- The responder answers with `STATE_BUNDLE` carrying up to 64 missing `GROUP_UPDATE`s from its update log, oldest first; the requester feeds them through the normal §6.1 pipeline (epoch-gap buffering orders them).
- The group Admin additionally republishes its latest `GROUP_UPDATE` for any `STATE_REQUEST` covering the group's current epoch, so a partitioned minority reconverges even when no peer retains history.

### 6.3 Persistence & Restart Semantics
- Each node persists to its state directory (file mode `0600`): identity keys, pinned roster, per-group epochs + membership + current/previous epoch keys, replay windows, and the seen-ID set.
- On restart the daemon reloads this state and resumes at its last epoch (never at epoch 0); updates missed during downtime arrive via §6.2 within one $T_a$ round.
- `membership_hash` disagreement at equal epochs (possible only under malicious double-signing) is surfaced as `ADMIN_DOUBLE_SIGN` (§7.4).

---

## 7. Anti-Replay, Validation & Conflict Defense

### 7.1 Gossip Plane Protection
- Guarded by the cryptographic hash `update_id` and the bounded LRU cache.
- Updates cannot be replayed across epochs because `new_epoch` must be strictly greater than the node's current epoch.

### 7.2 Data Plane Protection (Per-Sender Sliding Window)
For each group and epoch, receiving nodes track message counters from each known sender:
- **Last Seen Counter ($C_{\text{max}}$):** Highest counter observed from sender $S$.
- **Replay Window Bitmask:** A 64-bit sliding window tracking messages received out of order within $[C_{\text{max}} - 63, C_{\text{max}}]$.
- Any packet arriving with counter $C \le C_{\text{max}} - 64$ or with its corresponding bit already set in the bitmask is dropped with event `REPLAY_DETECTED`.
- The window is per (group, epoch, sender) and persists across restarts (§6.3).

### 7.3 `GROUP_MSG` Validation & Epoch Grace Keys
A receiver accepts a `GROUP_MSG` only if **all** of the following hold (checked in order):
1. `group_id` is a group the node belongs to, and `epoch` equals the node's local epoch — or `local_epoch - 1` within the grace window.
2. `sender_id` is a member of **that epoch's** pinned member map (a removed member's messages under a stale epoch key are dropped here once the update is applied).
3. The 4-byte nonce prefix equals the pinned `sender_prefix` from that member map entry (blocks prefix spoofing).
4. The counter passes the §7.2 sliding-window check for (group, epoch, sender).
5. AES-GCM decryption under $K_{\text{epoch}}$ succeeds — or, for grace-epoch messages, under $K_{e-1}$.

**Grace key policy:** at most two epoch keys are ever retained — $K_e$ and $K_{e-1}$ (for in-flight messages during a transition). $K_{e-2}$ is dropped the moment $K_e$ installs (§5.2 step 6). Grace-epoch messages use the *previous* epoch's membership for check (2).

### 7.4 Admin Double-Sign Detection (Fork Evidence)
If a node receives two valid Admin-signed `GROUP_UPDATE`s with the same $(\text{group\_id}, \text{new\_epoch})$ but differing `update_id` or content:
- It keeps the first-installed state (deterministic, no flapping),
- Logs `ADMIN_DOUBLE_SIGN` with both artifacts as evidence,
- Increments the `double_sign_detected` telemetry counter (consumed by `experiments/attack_metrics.py`).
This is *detection*, not prevention — consistent with the V1 Admin model's documented limitations.

---

## 8. Out-of-Band Control Plane Specification (Unix Domain Socket)

Every node daemon listens on a local Unix socket: `/tmp/gossip-sim/sockets/{node_id}.sock`.  
The protocol is request-response JSON-RPC 2.0.

**Access control:** the orchestrator creates the directory `0750` and each socket `0660`, owned by the invoking user (`SUDO_UID` when launched via sudo); the CLI must run as that owner. The control plane is **unauthenticated** — acceptable for a single-host testbed only. Secret-export methods (`node.secrets`) are refused unless the daemon was started with `--unsafe-allow-secret-export`.

### 8.1 Inspection Request (`node.inspect`)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "node.inspect",
  "params": {}
}
```

### 8.2 Inspection Response
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "node_id": "alice",
    "status": "ONLINE",
    "links": [
      {"peer": "bob", "iface": "vlk0a", "local_addr": "10.200.0.0", "remote_addr": "10.200.0.1", "port": 9000}
    ],
    "uptime_seconds": 342,
    "identity": {
      "ed25519_pubkey": "4f8a91bc...",
      "x25519_pubkey": "7a20c4d2...",
      "fingerprint": "SHA256:8D:31:..."
    },
    "peers": [
      {"node_id": "bob", "address": "10.200.0.1:9000", "status": "CONNECTED"}
    ],
    "groups": {
      "quantum-team": {
        "role": "ADMIN",
        "epoch": 7,
        "members": {"alice": "9f2c11a0", "bob": "3b7e44c1", "dave": "77aa02de"},
        "key_fingerprint": "8f01b2a9"
      }
    },
    "stats": {
      "direct_sent": 12,
      "direct_received": 11,
      "group_sent": 45,
      "group_received": 90,
      "gossip_propagated": 34,
      "replays_detected": 2,
      "signature_failures": 0,
      "decryption_failures": 1,
      "double_sign_detected": 0,
      "resync_rounds": 5
    }
  }
}
```

---

## 9. Error Codes & Rejection Reasons

| Code | Label | Cause |
|---|---|---|
| `ERR_SIG_INVALID` | Signature Invalid | Ed25519 verification of `GROUP_UPDATE` failed |
| `ERR_EPOCH_STALE` | Stale Epoch | Received update with epoch $\le$ current local epoch |
| `ERR_EPOCH_GAP` | Epoch Gap | Received update with epoch $> \text{current} + 1$ (buffered; `STATE_REQUEST` issued) |
| `ERR_UNAUTHORIZED` | Unauthorized Admin | Update signed by a key not matching the **pinned** group Admin key |
| `ERR_IDENTITY_UNKNOWN` | Unknown Identity | `HELLO` or envelope `sender_id` absent from the pinned roster manifest |
| `ERR_PREFIX_MISMATCH` | Sender Prefix Mismatch | `GROUP_MSG` nonce prefix $\ne$ pinned `sender_prefix` of the epoch's member map |
| `ERR_SENDER_NOT_MEMBER` | Sender Not In Membership | `GROUP_MSG` sender absent from the claimed epoch's member map |
| `ERR_REPLAY` | Replay Detected | `update_id` already in seen cache or data counter already seen |
| `ERR_DECRYPT_FAIL` | Decryption Failed | AES-GCM tag verification failure (tampered payload or bad key) |
| `ERR_KEY_UNWRAP` | Key Unwrap Failed | AES-KW integrity failure for recipient key blob |
| `ERR_PEER_UNREACHABLE` | Peer Unreachable | Socket connection refused or timed out |
| `EV_ADMIN_DOUBLE_SIGN` | Admin Double-Sign Evidence | Two valid Admin updates for the same $(\text{group\_id}, \text{new\_epoch})$ with different content (§7.4) |

---

## 10. Identity, Roster Distribution & Trust Model

1. **Roster manifest:** at `init` the orchestrator generates each node's Ed25519/X25519 keypairs (or collects self-generated public keys over UDS) and writes `roster.json`: `node_id` → `{ed25519_pubkey, x25519_pubkey, fingerprint}`, with `fingerprint = SHA256("gossip-sim-v1:fingerprint:v1|" || ed25519_pubkey || "|" || x25519_pubkey)` (hex). The manifest is distributed to each node's state directory (mode `0600`) before its daemon starts.
2. **Pinning rule:** nodes verify every security-relevant artifact against the pinned manifest — Admin signatures on `GROUP_UPDATE`, X25519 public keys used in wraps, and `HELLO` identity claims. First-seen bootstrap is explicitly forbidden: a spoofable first update would let an attacker pin a fake admin.
3. **`HELLO` binding:** the first frame on every data-plane connection is `{"version": 1, "type": "HELLO", "node_id": "...", "ed25519_pubkey": "b64", "timestamp": ...}`; the receiver checks `node_id → ed25519_pubkey` against the roster and rejects with `ERR_IDENTITY_UNKNOWN` on mismatch. A spoofed `HELLO` gains nothing for crypto state (all `GROUP_*` artifacts are independently authenticated); it only disambiguates the unsigned `DIRECT_MSG` test channel, which is explicitly outside the security model.
4. **Certificate layer:** `crypto/certificate.py` self-signed identity metadata exists for display and fingerprints only. There is no PKI, chain validation, or revocation in V1 — the orchestrator-manifested roster is the sole trust anchor (single-host testbed assumption, stated openly).
