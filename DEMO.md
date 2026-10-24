# Gossip-Encryption-Sim: Demo Flow & CLI Cheat Sheet

Complete command walkthrough with inline explanations, ordered logically for a live demonstration.

```bash
# ==============================================================================
# PHASE 1: INITIALIZATION & DAEMON STARTUP
# ==============================================================================

# Create network namespaces, /31 veth links (alice-bob-charlie-dave), keys, & roster
sudo python3 cli.py init --nodes alice,bob,charlie,dave --topology linear --force

# Launch node background daemons in namespaces (allow secret export for attack demos)
sudo python3 cli.py start --unsafe-allow-secret-export

# Verify simulation environment: running PIDs, links (UP), and group epochs
python3 cli.py status

# List all nodes, peer connections, and status
python3 cli.py node list


# ==============================================================================
# PHASE 2: DIRECT MESSAGING (PHYSICAL LINK ISOLATION PROOF)
# ==============================================================================

# Adjacent nodes: succeeds because Alice and Bob share an immediate veth link
python3 cli.py send alice bob "Hello Bob"

# Non-adjacent nodes: fails (ERR_PEER_UNREACHABLE) because no direct L3 route exists
python3 cli.py send alice charlie "Hello Charlie"


# ==============================================================================
# PHASE 3: SECURE GROUP CREATION & MEMBERSHIP (BACKWARD SECRECY)
# ==============================================================================

# Alice creates group 'sec-team' at Epoch 0 (Alice is Admin)
python3 cli.py group create alice sec-team

# Add Bob: advances to Epoch 1, rotates AES key K_1, wraps for Bob & Alice
python3 cli.py group join alice sec-team bob

# Add Charlie: advances to Epoch 2, rotates AES key K_2, wraps for Charlie, Bob, & Alice
python3 cli.py group join alice sec-team charlie

# Verify current membership and active epochs across nodes
python3 cli.py node list


# ==============================================================================
# PHASE 4: ENCRYPTED GROUP GOSSIP (MULTI-HOP PROPAGATION)
# ==============================================================================

# Alice encrypts with AES-256-GCM; Bob relays ciphertext; Charlie decrypts
python3 cli.py group send alice sec-team "Classified brief: deployment at 0400"

# Inspect Charlie's state: verify message received and decrypted in inbox
python3 cli.py node show charlie


# ==============================================================================
# PHASE 5: MEMBER REMOVAL & RE-KEYING (FORWARD SECRECY)
# ==============================================================================

# Add Dave to group: advances to Epoch 3 with new key K_3
python3 cli.py group join alice sec-team dave

# Alice sends message in Epoch 3; Dave can decrypt
python3 cli.py group send alice sec-team "Welcome Dave"
python3 cli.py node show dave

# Remove Dave: advances to Epoch 4, generates key K_4 wrapped ONLY for Alice, Bob, Charlie
python3 cli.py group leave alice sec-team dave

# Send message in Epoch 4: Dave receives gossiped frame but CANNOT decrypt
python3 cli.py group send alice sec-team "Dave removed: secret update"

# Inspect Dave: shows role REMOVED and decryption failure count incremented
python3 cli.py node show dave


# ==============================================================================
# PHASE 6: KERNEL NETWORK IMPAIRMENTS (tc netem)
# ==============================================================================

# Inject 100ms latency (+/- 20ms jitter) on link between Alice and Bob
sudo python3 cli.py network latency --link alice,bob --delay 100ms --jitter 20ms

# Inject 20% packet drop rate across Charlie's interfaces
sudo python3 cli.py network loss --node charlie --rate 20

# View all active kernel impairments across links
sudo python3 cli.py network show

# Send group message across impaired network
python3 cli.py group send alice sec-team "Testing under packet loss and latency"

# Clear all network impairments back to normal
sudo python3 cli.py network clear


# ==============================================================================
# PHASE 7: NETWORK PARTITION & ANTI-ENTROPY HEALING
# ==============================================================================

# Sever links between (Alice, Bob) and (Charlie, Dave)
sudo python3 cli.py network partition --group-a alice,bob --group-b charlie,dave

# Verify cut link state
sudo python3 cli.py network show

# Alice sends a message during partition (Charlie will not receive it yet)
python3 cli.py group send alice sec-team "Message during partition split"
python3 cli.py node show charlie

# Heal the partition (reconnects veth links)
sudo python3 cli.py network heal

# Wait 3 seconds for anti-entropy push-pull digest reconciliation, then inspect Charlie
sleep 3
python3 cli.py node show charlie


# ==============================================================================
# PHASE 8: ACTIVE ADVERSARIAL ATTACKS
# ==============================================================================

# 1. In-Transit Bit Tampering: corrupts next ciphertext from Alice to Bob
python3 cli.py attack tamper --from alice --to bob --kind msg
python3 cli.py group send alice sec-team "Tamper integrity test"
python3 cli.py node show bob  # Shows DECRYPT_FAIL (AES-GCM tag mismatch)

# 2. Replay Attack: re-injects captured message to Bob
python3 cli.py attack replay --target bob --kind msg
python3 cli.py node show bob  # Shows REPLAY_DETECTED (counter already seen)

# 3. Signature Forgery: injects unauthorized GROUP_UPDATE claiming to be Alice
python3 cli.py attack forge --as alice --to charlie --group sec-team
python3 cli.py node show charlie  # Shows UPDATE_REJECTED (ERR_SIG_INVALID)

# 4. Admin Double-Signing: forces Alice to sign two conflicting updates for same epoch
python3 cli.py attack double-sign --admin alice --group sec-team
python3 cli.py node show charlie  # Shows ADMIN_DOUBLE_SIGN detected

# 5. Gossip Suppression: mutes Bob so he drops all outgoing gossip frames
python3 cli.py attack suppress bob
python3 cli.py group send alice sec-team "Should be dropped by Bob"
python3 cli.py attack suppress bob --off  # Unmute Bob

# 6. Node Compromise: dumps Charlie's private keys and assesses impact radius
python3 cli.py attack compromise charlie

# Raw secret key export (manual audit)
python3 cli.py node secrets alice --unsafe


# ==============================================================================
# PHASE 9: RUNTIME TOPOLOGY MODIFICATIONS
# ==============================================================================

# Dynamically add a direct shortcut link between Alice and Charlie
sudo python3 cli.py link add alice charlie

# Verify direct message now works between Alice and Charlie
python3 cli.py send alice charlie "Shortcut link works!"

# Remove the shortcut link
sudo python3 cli.py link remove alice charlie


# ==============================================================================
# PHASE 10: CLEANUP & TEARDOWN
# ==============================================================================

# Stop node background daemons (state preserved)
python3 cli.py stop

# Completely delete namespaces, veth interfaces, and purge logs
sudo python3 cli.py destroy --purge-logs
```
