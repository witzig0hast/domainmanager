"""Append-only JSON-lines audit log."""
from __future__ import annotations

import json
import threading
import time
from collections import deque

from .config import settings

_lock = threading.Lock()
_PATH = settings.data_dir / "audit.log"


def log(event: str, ip: str = "", **details) -> None:
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, "ip": ip, **details}
    line = json.dumps(entry, ensure_ascii=False)
    with _lock:
        try:
            settings.data_dir.mkdir(parents=True, exist_ok=True)
            with _PATH.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
    print(f"AUDIT {line}", flush=True)


def tail(limit: int = 200) -> list[dict]:
    with _lock:
        try:
            with _PATH.open(encoding="utf-8") as fh:
                lines = deque(fh, maxlen=limit)
        except OSError:
            return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
