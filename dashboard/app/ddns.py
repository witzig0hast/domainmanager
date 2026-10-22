"""Manage the domain list of favonia/cloudflare-ddns via its env file, and ask the applier to recreate it."""
from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import threading
import time
from pathlib import Path

from .config import settings

HOST_RE = re.compile(r"^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_lock = threading.Lock()
MAX_BACKUPS = 10


class DdnsError(Exception):
    pass


def normalize(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if len(host) > 253 or not HOST_RE.match(host):
        raise DdnsError(f"Ungültiger Hostname: {host!r}")
    return host


def _split(value: str) -> list[str]:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return [d.strip().lower() for d in value.split(",") if d.strip()]


def _read_lines() -> list[str]:
    path = settings.ddns_env_file
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def read() -> dict[str, list[str]]:
    """Return {key: [domains]} for the configured domain keys only. Other keys (e.g. tokens) are never exposed."""
    out: dict[str, list[str]] = {k: [] for k in settings.ddns_domain_keys}
    for line in _read_lines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        if key in out:
            out[key] = _split(value)
    return out


def status() -> dict:
    path = settings.ddns_env_file
    return {
        "file": str(path),
        "exists": path.exists(),
        "writable": os.access(path.parent, os.W_OK) and (not path.exists() or os.access(path, os.W_OK)),
        "keys": list(settings.ddns_domain_keys),
    }


def _backup(path: Path) -> None:
    if not path.exists():
        return
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.bak-{stamp}")
    backup.write_bytes(path.read_bytes())
    os.chmod(backup, 0o600)
    backups = sorted(path.parent.glob(f"{path.name}.bak-*"))
    for old in backups[:-MAX_BACKUPS]:
        old.unlink(missing_ok=True)


def write(new: dict[str, list[str]]) -> dict[str, list[str]]:
    """Replace the domain keys in the env file, keeping every other line untouched."""
    for key in new:
        if key not in settings.ddns_domain_keys:
            raise DdnsError(f"Unbekannter Schlüssel: {key}")
    cleaned = {k: sorted(dict.fromkeys(normalize(d) for d in v)) for k, v in new.items()}
    path = settings.ddns_env_file
    with _lock:
        lines = _read_lines()
        seen: set[str] = set()
        out_lines = []
        for line in lines:
            stripped = line.strip()
            key = stripped.partition("=")[0].strip() if "=" in stripped and not stripped.startswith("#") else ""
            if key.startswith("export "):
                key = key[7:].strip()
            if key in cleaned:
                seen.add(key)
                if cleaned[key]:
                    out_lines.append(f"{key}={','.join(cleaned[key])}")
                continue
            out_lines.append(line)
        for key, domains in cleaned.items():
            if key not in seen and domains:
                out_lines.append(f"{key}={','.join(domains)}")
        _backup(path)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".ddns-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(out_lines) + "\n")
            os.chmod(tmp, 0o644)  # applier (root, no caps) must read it for docker compose
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
    return read()


# --- applier handshake (shared volume, no network, no Docker socket in this container) ---

def _applier_file(name: str) -> Path:
    return settings.applier_dir / name


def request_apply() -> str:
    if not settings.applier_enabled:
        raise DdnsError("Applier ist deaktiviert – bitte den DDNS-Container manuell neu erstellen.")
    nonce = secrets.token_hex(16)
    target = _applier_file("request.json")
    fd, tmp = tempfile.mkstemp(dir=settings.applier_dir, prefix=".req-", suffix=".tmp")
    with os.fdopen(fd, "w") as fh:
        json.dump({"nonce": nonce, "ts": int(time.time())}, fh)
    os.chmod(tmp, 0o644)
    os.replace(tmp, target)
    return nonce


def applier_status() -> dict:
    hb = _applier_file("heartbeat")
    try:
        age = time.time() - hb.stat().st_mtime
    except OSError:
        age = None
    result = None
    try:
        result = json.loads(_applier_file("result.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return {
        "enabled": settings.applier_enabled,
        "alive": age is not None and age < 30,
        "pending": _applier_file("request.json").exists(),
        "last_result": result,
    }
