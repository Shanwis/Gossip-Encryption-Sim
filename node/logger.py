"""Structured JSONL event logger.

Every record carries ``ts`` (host wall clock, shared by all namespaces on the
testbed), ``node`` and ``event``; experiments parse these files directly.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from typing import IO, Any

SECURITY_EVENTS = {
    "HELLO_REJECTED",
    "UPDATE_REJECTED",
    "REPLAY_DETECTED",
    "DECRYPT_FAIL",
    "MSG_REJECTED",
    "KEY_UNWRAP_FAIL",
    "ADMIN_DOUBLE_SIGN",
    "ATTACK_INJECTED",
    "SECRETS_EXPORTED",
    "FRAME_REJECTED",
}


class EventLogger:
    def __init__(self, node_id: str, path: str | None = None, stream: IO[str] | None = None):
        self.node_id = node_id
        self.path = path
        self._lock = threading.Lock()
        self._fh: IO[str] | None = stream
        if path is not None and stream is None:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self._fh = open(path, "a", encoding="utf-8")
        self.recent_security: deque[dict] = deque(maxlen=50)

    def log(self, event: str, **fields: Any) -> dict:
        record = {"ts": time.time(), "node": self.node_id, "event": event, **fields}
        if event in SECURITY_EVENTS:
            self.recent_security.append(record)
        if self._fh is not None:
            line = json.dumps(record, sort_keys=True, default=str)
            with self._lock:
                self._fh.write(line + "\n")
                self._fh.flush()
        return record

    def close(self) -> None:
        if self._fh is not None and self.path is not None:
            self._fh.close()
            self._fh = None


def read_events(path: str) -> list[dict]:
    """Parse a JSONL log, skipping a possibly truncated trailing line."""
    events = []
    if not os.path.exists(path):
        return events
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events
