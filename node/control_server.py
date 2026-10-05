"""Out-of-band control plane: JSON-RPC 2.0 over a Unix domain socket (protocol §8).

Requests and responses use the same 4-byte big-endian length-prefixed framing
as the data plane. Pathname UDS live on the host filesystem, so the CLI can
reach a node even when its namespace is fully partitioned.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
from typing import Any, Awaitable, Callable

from node.messaging import MAX_FRAME, ProtocolError

Handler = Callable[[dict], Awaitable[Any]]

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_SERVER_ERROR = -32000
UDS_PATH_MAX = 107


class RPCError(Exception):
    def __init__(self, code: str, message: str, rpc_code: int = JSONRPC_SERVER_ERROR):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.rpc_code = rpc_code


def _pack(obj: dict) -> bytes:
    payload = json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise ValueError("control frame too large")
    return struct.pack(">I", len(payload)) + payload


class ControlServer:
    def __init__(self, path: str, handlers: dict[str, Handler], socket_mode: int = 0o660):
        if len(path.encode()) > UDS_PATH_MAX:
            raise ValueError(f"UDS path too long ({len(path)} > {UDS_PATH_MAX}): {path}")
        self.path = path
        self.handlers = handlers
        self.socket_mode = socket_mode
        self.server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if os.path.exists(self.path):
            os.unlink(self.path)
        self.server = await asyncio.start_unix_server(self._handle, path=self.path)
        os.chmod(self.path, self.socket_mode)

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        if os.path.exists(self.path):
            os.unlink(self.path)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                try:
                    header = await reader.readexactly(4)
                except asyncio.IncompleteReadError:
                    break
                (length,) = struct.unpack(">I", header)
                if length > MAX_FRAME:
                    break
                raw = await reader.readexactly(length)
                writer.write(_pack(await self._dispatch(raw)))
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    async def _dispatch(self, raw: bytes) -> dict:
        try:
            request = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": JSONRPC_PARSE_ERROR, "message": "parse error"}}
        req_id = request.get("id") if isinstance(request, dict) else None
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": JSONRPC_INVALID_REQUEST, "message": "invalid request"}}
        handler = self.handlers.get(request["method"])
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": JSONRPC_METHOD_NOT_FOUND, "message": f"unknown method {request['method']}"},
            }
        params = request.get("params") or {}
        try:
            if not isinstance(params, dict):
                raise RPCError("ERR_INVALID_PARAMS", "params must be an object")
            result = await handler(params)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        except (RPCError, ProtocolError) as exc:
            code = exc.code
            message = exc.message
        except (KeyError, TypeError, ValueError) as exc:
            code, message = "ERR_INVALID_PARAMS", f"{type(exc).__name__}: {exc}"
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": JSONRPC_SERVER_ERROR, "message": message, "data": {"code": code}},
        }


def rpc_call(path: str, method: str, params: dict | None = None, timeout: float = 10.0) -> Any:
    """Synchronous JSON-RPC client used by the CLI/orchestrator.

    Raises :class:`RPCError` for JSON-RPC errors and ``OSError`` if the socket is unreachable.
    """
    request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(path)
        sock.sendall(_pack(request))
        header = _recv_exact(sock, 4)
        (length,) = struct.unpack(">I", header)
        response = json.loads(_recv_exact(sock, length).decode("utf-8"))
    if "error" in response:
        err = response["error"]
        raise RPCError(err.get("data", {}).get("code", "ERR_RPC"), err.get("message", "error"), err.get("code", 0))
    return response.get("result")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("control socket closed")
        buf.extend(chunk)
    return bytes(buf)
