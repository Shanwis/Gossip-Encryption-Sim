# Gossip Encryption Sim

## Members

- Adnan Omar (2023BCS0035)
- Ashwin S (2023BCS0044)
- Elhan B Thomas (2023BCS0119)
- Muntasir V P (2023BCS0191)

## What it is

A Linux-namespace testbed for secure group messaging over epidemic gossip
(see [IDEA.md](IDEA.md) for the concept, [PLAN.md](PLAN.md) for the implemented
plan and [docs/protocol.md](docs/protocol.md) for the normative wire protocol):

- every node is a daemon in its own network namespace; every topology edge is a
  dedicated veth pair with a `/31` (non-adjacent nodes have no path at all);
- group messages use AES-256-GCM with admin-assigned `prefix || counter` nonces;
  membership changes are Admin-signed (Ed25519) `GROUP_UPDATE`s carrying a fresh
  random epoch key wrapped per member (X25519 + HKDF-SHA256 + AES-256-KW);
- updates spread by rumor-mongering (fanout *k*) plus push-pull anti-entropy;
- `tc netem` / link cuts inject loss, latency and partitions; an attack engine
  drives replay, tampering, forgery, admin double-signing, gossip suppression and
  node compromise;
- an out-of-band JSON-RPC control plane over Unix sockets, JSONL telemetry, and
  seeded experiments with Matplotlib plots.

## Requirements

- Linux with network-namespace support, `iproute2` (`ip`, `tc`) and `iptables`;
  root (sudo) for anything that touches namespaces/links.
- Python ≥ 3.10.
- `tc netem` needs the kernel's `sch_netem` module. Without it, packet **loss**
  falls back automatically to `iptables` random drops; latency/jitter/reorder/
  duplicate report a clear error.

```bash
pip install -e ".[dev]"          # or: pip install cryptography networkx pandas matplotlib pytest pytest-asyncio
```

`pip install -e .` also provides a `gossip-sim` command; `python3 cli.py` is equivalent.

## Quick start

```bash
sudo python3 cli.py init --nodes alice,bob,charlie,dave --topology linear
sudo python3 cli.py start
python3 cli.py node list
python3 cli.py send alice bob "Hello Bob"          # adjacent: SENT
python3 cli.py send alice charlie "Hi"             # ERR_PEER_UNREACHABLE: no link by construction

python3 cli.py group create alice security-team
python3 cli.py group join alice security-team bob
python3 cli.py group join alice security-team charlie
python3 cli.py group send alice security-team "Top secret payload"
python3 cli.py group leave alice security-team charlie
python3 cli.py group send alice security-team "Charlie should not see this"
python3 cli.py node show charlie                   # role REMOVED, decryption_failures=1

sudo python3 cli.py network partition --group-a alice,bob --group-b charlie,dave
sudo python3 cli.py network heal                   # anti-entropy reconverges
sudo python3 cli.py destroy                        # idempotent teardown
```

Node commands talk to `/tmp/gossip-sim/sockets/<node>.sock` and must run as the
user that invoked `sudo` (daemons drop privileges to `SUDO_UID`). Use `--home`
or `GOSSIP_SIM_HOME` (with `sudo -E`) to relocate the simulator directory.

### Command reference

| Area | Commands |
|---|---|
| lifecycle | `init --nodes <list\|N> --topology linear\|ring\|star\|full\|random [--edges a:b,...] [--seed]`, `start [--fanout 3] [--anti-entropy-interval 2] [--unsafe-allow-secret-export\|--unsafe-nodes a,b]`, `stop`, `status`, `destroy [--purge-logs]` |
| topology | `link add <u> <v>`, `link remove <u> <v>` |
| messaging | `send <from> <to> "<msg>"`, `group create\|join\|leave <admin> <group> [node]`, `group send <from> <group> "<msg>"` |
| inspection | `node list`, `node show <node> [--json]`, `node secrets <node> --unsafe` |
| network | `network loss --link a,b\|--node n --rate 10`, `network latency --link a,b --delay 100ms --jitter 20ms`, `network partition --group-a .. --group-b ..`, `network heal`, `network clear`, `network show` |
| attacks | `attack replay --target n [--via m] [--kind msg\|update]`, `attack tamper --from m --to n [--kind msg\|update]`, `attack forge --as a --to n`, `attack double-sign --admin a --group g`, `attack suppress <node> [--off]`, `attack compromise <node>` |

## Tests

```bash
python3 -m pytest                                  # everything; root suites skip when not root
python3 -m pytest tests/test_crypto.py tests/test_group_state.py tests/test_gossip.py tests/test_resync.py
sudo -E python3 -m pytest tests/test_namespace.py tests/test_attacks.py
```

## Experiments

All need root; each takes `--quick` for a short smoke run and writes JSON to
`experiments/data/`.

```bash
sudo -E python3 -m experiments.convergence          # convergence vs loss (linear/ring/random) + fanout sweep
sudo -E python3 -m experiments.partition_recovery   # partition heal + anti-entropy-only recovery
sudo -E python3 -m experiments.churn_resilience     # throughput/latency under join/leave churn
sudo -E python3 -m experiments.attack_metrics       # detection rate + time-to-detect per attack
python3 -m experiments.plotter                      # PNG + CSV into experiments/plots/
```

## Layout

```text
cli.py                 gossip-sim CLI
crypto/                encoding, identity (Ed25519), key_agreement (X25519/HKDF/AES-KW), symmetric (AES-GCM), certificate, engine facade
node/                  daemon (asyncio TCP + UDS), messaging (framing, GROUP_MSG pipeline), gossip (updates, anti-entropy), state, control_server, logger
simulator/             orchestrator (ledger, lifecycle), namespace, topology, network_impairer, attack_engine
experiments/           harness + four benchmarks + plotter
tests/                 unit, mock-socket, localhost-daemon and root integration tests
docs/protocol.md       wire protocol v1.0.1
```

## Limitations (V1, by design)

- The Admin is a single point of failure and a malicious Admin is *detected*
  (`ADMIN_DOUBLE_SIGN`), not prevented.
- The UDS control plane is unauthenticated (the host is the trust boundary);
  `DIRECT_MSG` is an unsigned test channel.
- Key erasure is best-effort (CPython cannot guarantee zeroisation).
- The group→admin binding is pinned from the first authenticated update for a
  group id; two roster members racing to create the same group id is unresolved.
