"""Node daemon: the process executed inside a node's network namespace.

    ip netns exec netns-alice python3 -m node.daemon --id alice --home /tmp/gossip-sim

Boot order (protocol §6.3): drop privileges -> load identity + pinned roster ->
restore persisted state -> UDS control server -> TCP data plane -> anti-entropy.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import random
import signal
import socket
import sys
import time

from crypto.certificate import display_fingerprint, issue_self_signed
from crypto.encoding import b64e
from crypto.symmetric import key_fingerprint
from node.control_server import ControlServer, RPCError
from node.gossip import DEFAULT_FANOUT, GossipEngine
from node.logger import EventLogger
from node.messaging import (
    ERR_INVALID_PARAMS,
    ERR_PEER_UNREACHABLE,
    ERR_UNKNOWN_GROUP,
    ERR_UNSAFE_DISABLED,
    FrameError,
    MessageRouter,
    Outbox,
    ProtocolError,
    encode_frame,
    make_hello,
    read_frame,
    verify_hello,
)
from node.state import NodeState, StatePaths, default_home

CONNECT_TIMEOUT = 3.0
WRITE_TIMEOUT = 5.0
HELLO_TIMEOUT = 5.0
TCP_USER_TIMEOUT_MS = 5000
MAX_QUEUE = 1024
BACKOFF_MIN, BACKOFF_MAX = 0.25, 2.0

STAT_KEYS = (
    "direct_sent",
    "direct_received",
    "group_sent",
    "group_received",
    "group_relayed",
    "group_duplicates",
    "gossip_propagated",
    "gossip_suppressed",
    "duplicates_dropped",
    "stale_updates",
    "epoch_gaps",
    "replays_detected",
    "signature_failures",
    "unauthorized_updates",
    "unknown_identity",
    "malformed_updates",
    "malformed_frames",
    "decryption_failures",
    "key_unwrap_failures",
    "prefix_mismatches",
    "non_member_rejections",
    "stale_messages",
    "double_sign_detected",
    "resync_rounds",
    "resync_requests",
    "resync_bundles_sent",
    "resync_updates_applied",
    "hello_rejected",
    "frames_dropped",
    "attacks_injected",
)


class PeerChannel:
    """One outbound TCP connection per neighbour, fed by a bounded queue."""

    def __init__(self, daemon: "NodeDaemon", peer: str):
        self.daemon = daemon
        self.peer = peer
        self.queue: asyncio.Queue = asyncio.Queue()
        self.writer: asyncio.StreamWriter | None = None
        self.status = "IDLE"
        self.connected_since: float | None = None
        self.down_until = 0.0
        self.backoff = BACKOFF_MIN
        self.closed = False
        self.task = asyncio.create_task(self._run())

    @property
    def state(self) -> NodeState:
        return self.daemon.state

    def enqueue(self, data: bytes, fut: asyncio.Future | None = None) -> bool:
        if self.closed:
            return False
        if fut is None and time.monotonic() < self.down_until:
            self.state.stats["frames_dropped"] += 1
            return False
        if self.queue.qsize() >= MAX_QUEUE:
            _, old_fut = self.queue.get_nowait()
            self.state.stats["frames_dropped"] += 1
            if old_fut is not None and not old_fut.done():
                old_fut.set_exception(ProtocolError(ERR_PEER_UNREACHABLE, "send queue overflow"))
        self.queue.put_nowait((data, fut))
        return True

    async def _connect(self) -> None:
        link = self.state.links[self.peer]
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(link["remote_addr"], int(link.get("port", self.state.port))), CONNECT_TIMEOUT
        )
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if hasattr(socket, "TCP_USER_TIMEOUT"):
                # Abort connections whose data stays unacked (cut links) instead of
                # waiting out TCP's exponential retransmission backoff.
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, TCP_USER_TIMEOUT_MS)
        writer.write(encode_frame(make_hello(self.state)))
        self.writer = writer
        asyncio.create_task(self._watch_eof(reader, writer))
        if self.status != "CONNECTED":
            self.daemon.logger.log("PEER_CONNECTED", peer=self.peer, address=link["remote_addr"])
        self.status = "CONNECTED"
        self.connected_since = time.time()

    async def _watch_eof(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.read()
        except (ConnectionError, OSError):
            pass
        if self.writer is writer:
            self._drop_writer()

    def _drop_writer(self) -> None:
        if self.writer is not None:
            self.writer.close()
            self.writer = None
        self.connected_since = None

    async def _run(self) -> None:
        while not self.closed:
            data, fut = await self.queue.get()
            try:
                if self.writer is None:
                    await self._connect()
                self.writer.write(data)
                await asyncio.wait_for(self.writer.drain(), WRITE_TIMEOUT)
                self.backoff = BACKOFF_MIN
                if fut is not None and not fut.done():
                    fut.set_result(True)
            except asyncio.CancelledError:
                raise
            except (OSError, asyncio.TimeoutError, ConnectionError, KeyError) as exc:
                self._drop_writer()
                if self.status != "DOWN":
                    self.daemon.logger.log("PEER_DOWN", peer=self.peer, reason=f"{type(exc).__name__}: {exc}")
                self.status = "DOWN"
                self.down_until = time.monotonic() + self.backoff
                self.backoff = min(self.backoff * 2, BACKOFF_MAX)
                error = ProtocolError(ERR_PEER_UNREACHABLE, f"{self.peer}: {type(exc).__name__}: {exc}")
                if fut is not None and not fut.done():
                    fut.set_exception(error)
                self.state.stats["frames_dropped"] += 1
                while not self.queue.empty():  # anti-entropy re-delivers what matters
                    _, queued_fut = self.queue.get_nowait()
                    self.state.stats["frames_dropped"] += 1
                    if queued_fut is not None and not queued_fut.done():
                        queued_fut.set_exception(error)

    async def close(self) -> None:
        self.closed = True
        self.task.cancel()
        try:
            await self.task
        except (asyncio.CancelledError, Exception):
            pass
        self._drop_writer()


class PeerTransport:
    def __init__(self, daemon: "NodeDaemon"):
        self.daemon = daemon
        self.channels: dict[str, PeerChannel] = {}

    def neighbors(self) -> list[str]:
        return self.daemon.state.neighbors()

    def channel(self, peer: str) -> PeerChannel:
        ch = self.channels.get(peer)
        if ch is None or ch.closed:
            ch = self.channels[peer] = PeerChannel(self.daemon, peer)
        return ch

    def send(self, peer: str, frame: dict) -> bool:
        if peer not in self.daemon.state.links:
            return False
        try:
            data = encode_frame(frame)
        except FrameError as exc:
            self.daemon.logger.log("FRAME_REJECTED", code="ERR_MALFORMED", reason=str(exc), direction="out")
            return False
        return self.channel(peer).enqueue(data)

    async def send_now(self, peer: str, frame: dict, timeout: float = CONNECT_TIMEOUT + WRITE_TIMEOUT) -> None:
        if peer not in self.daemon.state.links:
            raise ProtocolError(
                ERR_PEER_UNREACHABLE, f"no link to {peer}: non-adjacent nodes have no network path by construction"
            )
        fut = asyncio.get_running_loop().create_future()
        self.channel(peer).enqueue(encode_frame(frame), fut)
        try:
            await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError as exc:
            raise ProtocolError(ERR_PEER_UNREACHABLE, f"timed out sending to {peer}") from exc

    async def drop(self, peer: str) -> None:
        ch = self.channels.pop(peer, None)
        if ch is not None:
            await ch.close()

    async def close(self) -> None:
        for peer in list(self.channels):
            await self.drop(peer)


class NodeDaemon:
    def __init__(
        self,
        state: NodeState,
        paths: StatePaths,
        logger: EventLogger,
        *,
        fanout: int = DEFAULT_FANOUT,
        anti_entropy_interval: float = 2.0,
        seed: int | None = None,
        unsafe_secret_export: bool = False,
        host: str = "0.0.0.0",
        namespace: str | None = None,
    ):
        self.state = state
        self.paths = paths
        self.logger = logger
        self.host = host
        self.namespace = namespace
        self.anti_entropy_interval = anti_entropy_interval
        self.unsafe_secret_export = unsafe_secret_export
        self.rng = random.Random(f"{seed}:{state.node_id}") if seed is not None else random.Random()
        self.transport = PeerTransport(self)
        self.outbox = Outbox(state, self.transport, logger)
        self.gossip = GossipEngine(state, self.outbox, logger, fanout=fanout, rng=self.rng)
        self.router = MessageRouter(state, self.gossip, self.outbox, logger)
        self.certificate = issue_self_signed(state.node_id, state.identity, state.kex.public_bytes())
        self.control = ControlServer(paths.socket(state.node_id), self._handlers())
        self.server: asyncio.base_events.Server | None = None
        self.inbound: dict[str, set[asyncio.StreamWriter]] = {}
        self._tasks: list[asyncio.Task] = []
        self._stop: asyncio.Event | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        self._stop = asyncio.Event()
        self.state.started_at = time.time()
        await self.control.start()
        self.server = await asyncio.start_server(self._handle_inbound, self.host, self.state.port, reuse_address=True)
        self._tasks.append(asyncio.create_task(self._anti_entropy_loop()))
        self.logger.log(
            "NODE_STARTED",
            pid=os.getpid(),
            port=self.state.port,
            neighbors=self.state.neighbors(),
            restored_groups={gid: g.epoch for gid, g in self.state.groups.items()},
        )

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks.clear()
        if self.server is not None:
            self.server.close()
            for writers in self.inbound.values():
                for writer in writers:
                    writer.close()
            await self.server.wait_closed()
            self.server = None
        await self.transport.close()
        await self.control.stop()
        self.state.save()
        self.logger.log("NODE_STOPPED")

    async def run(self) -> None:
        await self.start()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self._stop.set)
            except (NotImplementedError, RuntimeError):
                pass
        print(f"READY {self.state.node_id} pid={os.getpid()}", flush=True)
        await self._stop.wait()
        await self.stop()

    def request_stop(self) -> None:
        if self._stop is not None:
            self._stop.set()

    async def _anti_entropy_loop(self) -> None:
        while True:
            await asyncio.sleep(self.anti_entropy_interval * self.rng.uniform(0.5, 1.5))
            try:
                self.gossip.anti_entropy_round()
            except Exception as exc:  # never let the loop die
                self.logger.log("INTERNAL_ERROR", where="anti_entropy", error=repr(exc))

    # ------------------------------------------------------------------
    # Data plane (inbound)
    # ------------------------------------------------------------------
    async def _handle_inbound(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            for opt, value in (("TCP_KEEPIDLE", 5), ("TCP_KEEPINTVL", 2), ("TCP_KEEPCNT", 3)):
                if hasattr(socket, opt):
                    sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), value)
        peer = None
        try:
            hello = await asyncio.wait_for(read_frame(reader), HELLO_TIMEOUT)
            peer = verify_hello(self.state, hello)
            previous = self.inbound.setdefault(peer, set())
            for old in list(previous):  # a fresh HELLO supersedes stale inbound connections
                old.close()
            previous.clear()
            previous.add(writer)
            while True:
                frame = await read_frame(reader)
                try:
                    self.router.handle_frame(frame, peer)
                except Exception as exc:  # a bug in one frame must not kill the link
                    self.logger.log("INTERNAL_ERROR", where="handle_frame", error=repr(exc), frame_type=frame.get("type"))
        except ProtocolError as exc:
            self.state.stats["hello_rejected"] += 1
            self.logger.log("HELLO_REJECTED", code=exc.code, reason=exc.message)
        except FrameError as exc:
            self.state.stats["malformed_frames"] += 1
            self.logger.log("FRAME_REJECTED", code="ERR_MALFORMED", reason=str(exc), from_peer=peer)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            if peer is not None:
                self.inbound.get(peer, set()).discard(writer)
            writer.close()

    # ------------------------------------------------------------------
    # Control plane handlers
    # ------------------------------------------------------------------
    def _handlers(self) -> dict:
        return {
            "node.inspect": self.rpc_inspect,
            "node.send_direct": self.rpc_send_direct,
            "node.group_create": self.rpc_group_create,
            "node.group_join": self.rpc_group_join,
            "node.group_leave": self.rpc_group_leave,
            "node.group_rekey": self.rpc_group_rekey,
            "node.group_send": self.rpc_group_send,
            "node.inject_attack": self.rpc_inject_attack,
            "node.secrets": self.rpc_secrets,
            "node.peer_add": self.rpc_peer_add,
            "node.peer_remove": self.rpc_peer_remove,
        }

    def inspect(self) -> dict:
        s = self.state
        links = [
            {
                "peer": peer,
                "iface": link.get("iface"),
                "local_addr": link.get("local_addr"),
                "remote_addr": link.get("remote_addr"),
                "port": int(link.get("port", s.port)),
                "link_index": link.get("link_index"),
            }
            for peer, link in sorted(s.links.items())
        ]
        peers = []
        for peer, link in sorted(s.links.items()):
            ch = self.transport.channels.get(peer)
            outbound = ch.status if ch else "IDLE"
            inbound = bool(self.inbound.get(peer))
            connected = outbound == "CONNECTED" or inbound
            since = ch.connected_since if ch and ch.connected_since else None
            peers.append(
                {
                    "node_id": peer,
                    "address": f"{link.get('remote_addr')}:{link.get('port', s.port)}",
                    "status": "CONNECTED" if connected else ("DOWN" if outbound == "DOWN" else "DISCONNECTED"),
                    "outbound": outbound,
                    "inbound": inbound,
                    "connection_uptime": round(time.time() - since, 1) if since else None,
                }
            )
        groups = {}
        for gid, g in sorted(s.groups.items()):
            key = g.keys.get(g.epoch)
            groups[gid] = {
                "role": g.status,
                "admin_id": g.admin_id,
                "epoch": g.epoch,
                "members": dict(sorted(g.members.items())),
                "membership_hash": g.membership_hash,
                "key_fingerprint": key_fingerprint(key) if key else None,
                "grace_epoch": g.epoch - 1 if (g.epoch - 1) in g.keys else None,
                "send_counter": g.send_counter,
                "pending_updates": sorted(self.gossip.pending.get(gid, {})),
                "update_log_size": len(s.update_logs.get(gid, [])),
            }
        stats = {key: 0 for key in STAT_KEYS}
        stats.update(s.stats)
        return {
            "node_id": s.node_id,
            "status": "ONLINE",
            "pid": os.getpid(),
            "namespace": self.namespace,
            "port": s.port,
            "links": links,
            "uptime_seconds": round(time.time() - s.started_at, 1),
            "identity": {
                "ed25519_pubkey": s.identity.public_bytes().hex(),
                "x25519_pubkey": s.kex.public_bytes().hex(),
                "fingerprint": display_fingerprint(self.certificate.fingerprint),
                "fingerprint_hex": self.certificate.fingerprint,
                "issuer": self.certificate.issuer,
                "not_before": self.certificate.not_before,
                "not_after": self.certificate.not_after,
            },
            "roster": {nid: s.roster.entries[nid].fingerprint for nid in s.roster.node_ids()},
            "peers": peers,
            "groups": groups,
            "stats": stats,
            "security": {
                "compromised": s.compromised,
                "attack_modes": {"tamper": dict(s.attack_modes["tamper"]), "suppress": s.attack_modes["suppress"]},
                "recent_events": list(self.logger.recent_security)[-10:],
            },
            "inbox": list(s.inbox)[-10:],
            "direct_inbox": list(s.direct_inbox)[-10:],
            "config": {
                "fanout": self.gossip.fanout,
                "anti_entropy_interval": self.anti_entropy_interval,
                "unsafe_secret_export": self.unsafe_secret_export,
            },
        }

    async def rpc_inspect(self, params: dict) -> dict:
        return self.inspect()

    async def rpc_send_direct(self, params: dict) -> dict:
        to, text = params["to"], str(params["message"])
        frame = self.router.make_direct(to, text)
        await self.transport.send_now(to, frame)
        self.state.stats["direct_sent"] += 1
        self.logger.log("DIRECT_MSG_SENT", recipient_id=to, msg_id=frame["msg_id"])
        return {"msg_id": frame["msg_id"], "to": to, "status": "SENT"}

    @staticmethod
    def _summary(update: dict) -> dict:
        return {
            "group_id": update["group_id"],
            "epoch": update["new_epoch"],
            "update_id": update["update_id"],
            "action": update["action"],
            "target": update["target_member"],
            "members": sorted(update["members"]),
            "committed_at": time.time(),
        }

    async def rpc_group_create(self, params: dict) -> dict:
        return self._summary(self.gossip.create_group(params["group_id"]))

    async def rpc_group_join(self, params: dict) -> dict:
        return self._summary(self.gossip.add_member(params["group_id"], params["member"]))

    async def rpc_group_leave(self, params: dict) -> dict:
        return self._summary(self.gossip.remove_member(params["group_id"], params["member"]))

    async def rpc_group_rekey(self, params: dict) -> dict:
        return self._summary(self.gossip.rekey(params["group_id"]))

    async def rpc_group_send(self, params: dict) -> dict:
        frame = self.router.send_group(params["group_id"], str(params["message"]))
        return {
            "group_id": frame["group_id"],
            "epoch": frame["epoch"],
            "counter": frame["counter"],
            "msg_id": frame["msg_id"],
            "sent_at": time.time(),
        }

    async def rpc_inject_attack(self, params: dict) -> dict:
        attack = params.get("attack")
        if attack == "replay":
            return self.router.attack_replay(params["target"], params.get("kind", "msg"))
        if attack == "tamper":
            return self.router.arm_tamper(params["target"], params.get("kind", "msg"), int(params.get("count", 1)))
        if attack == "forge":
            target = params["target"]
            if target not in self.state.links:
                raise ProtocolError(ERR_PEER_UNREACHABLE, f"{target} is not adjacent to {self.state.node_id}")
            gid = params.get("group_id") or next(iter(sorted(self.state.groups)), None)
            if gid is None:
                raise ProtocolError(ERR_UNKNOWN_GROUP, "no group known to forge an update for")
            update = self.gossip.forge_update(gid, params["as"])
            self.router.transport_send_raw(target, update)
            self.state.stats["attacks_injected"] += 1
            record = self.logger.log(
                "ATTACK_INJECTED", attack="forge", target=target, claimed_admin=params["as"], group_id=gid, update_id=update["update_id"]
            )
            return {"attack": "forge", "target": target, "group_id": gid, "update_id": update["update_id"], "ts": record["ts"]}
        if attack == "double_sign":
            first, second, injected_at = self.gossip.double_sign(params["group_id"])
            return {
                "attack": "double_sign",
                "group_id": params["group_id"],
                "epoch": first["new_epoch"],
                "update_ids": [first["update_id"], second["update_id"]],
                "ts": injected_at,
            }
        if attack == "suppress":
            enabled = bool(params.get("enabled", True))
            self.state.attack_modes["suppress"] = enabled
            self.logger.log("ATTACK_ARMED" if enabled else "ATTACK_DISARMED", attack="suppress")
            return {"attack": "suppress", "enabled": enabled}
        if attack == "clear":
            self.state.attack_modes["tamper"].clear()
            self.state.attack_modes["suppress"] = False
            self.logger.log("ATTACK_DISARMED", attack="all")
            return {"attack": "clear"}
        raise ProtocolError(ERR_INVALID_PARAMS, f"unknown attack {attack!r}")

    async def rpc_secrets(self, params: dict) -> dict:
        if not self.unsafe_secret_export:
            raise RPCError(
                ERR_UNSAFE_DISABLED, "secret export refused: daemon not started with --unsafe-allow-secret-export"
            )
        s = self.state
        s.compromised = True
        result = {
            "node_id": s.node_id,
            "ed25519_private": b64e(s.identity.private_bytes()),
            "x25519_private": b64e(s.kex.private_bytes()),
            "group_keys": {gid: {str(e): b64e(k) for e, k in sorted(g.keys.items())} for gid, g in sorted(s.groups.items())},
            "exported_at": time.time(),
        }
        self.logger.log("SECRETS_EXPORTED", groups={gid: sorted(g.keys) for gid, g in s.groups.items()})
        return result

    async def rpc_peer_add(self, params: dict) -> dict:
        peer = params["peer"]
        if peer not in self.state.roster:
            raise ProtocolError(ERR_INVALID_PARAMS, f"{peer} is not in the roster")
        link = {k: params[k] for k in ("peer", "iface", "local_addr", "remote_addr")}
        link["port"] = int(params.get("port", self.state.port))
        link["link_index"] = params.get("link_index")
        self.state.links[peer] = link
        self.state.save_config()
        await self.transport.drop(peer)
        self.logger.log("PEER_ADDED", peer=peer, remote_addr=link["remote_addr"])
        return {"peer": peer, "neighbors": self.state.neighbors()}

    async def rpc_peer_remove(self, params: dict) -> dict:
        peer = params["peer"]
        self.state.links.pop(peer, None)
        self.state.save_config()
        await self.transport.drop(peer)
        for writer in self.inbound.pop(peer, set()):
            writer.close()
        self.logger.log("PEER_REMOVED", peer=peer)
        return {"peer": peer, "neighbors": self.state.neighbors()}


def drop_privileges(uid: int | None, gid: int | None) -> None:
    if uid is None or os.geteuid() != 0:
        return
    os.setgroups([])
    os.setgid(gid if gid is not None else uid)
    os.setuid(uid)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="node.daemon", description="Gossip simulator node daemon")
    p.add_argument("--id", required=True, help="node identifier")
    p.add_argument("--home", default=default_home(), help="simulator home directory")
    p.add_argument("--port", type=int, default=None, help="TCP data-plane port (default: from config)")
    p.add_argument("--host", default="0.0.0.0", help="bind address (all link addresses by default)")
    p.add_argument("--fanout", type=int, default=DEFAULT_FANOUT)
    p.add_argument("--anti-entropy-interval", type=float, default=2.0)
    p.add_argument("--seed", type=int, default=None, help="RNG seed for fanout / peer sampling")
    p.add_argument("--namespace", default=None, help="network namespace name (informational)")
    p.add_argument("--unsafe-allow-secret-export", action="store_true", help="enable node.secrets (experiments only)")
    p.add_argument("--uid", type=int, default=None, help="drop privileges to this uid after startup")
    p.add_argument("--gid", type=int, default=None)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    drop_privileges(args.uid, args.gid)
    os.umask(0o077)
    paths = StatePaths(args.home, args.id)
    state = NodeState.from_state_dir(paths.state_dir())
    if args.port is not None:
        state.port = args.port
    logger = EventLogger(args.id, paths.log())
    daemon = NodeDaemon(
        state,
        paths,
        logger,
        fanout=args.fanout,
        anti_entropy_interval=args.anti_entropy_interval,
        seed=args.seed,
        unsafe_secret_export=args.unsafe_allow_secret_export,
        host=args.host,
        namespace=args.namespace,
    )
    try:
        asyncio.run(daemon.run())
    finally:
        logger.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
