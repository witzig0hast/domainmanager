"""Read the domain list of an existing favonia/cloudflare-ddns setup (compose file, .env, env_file)
or from pasted text. Only DOMAINS/IP4_DOMAINS/IP6_DOMAINS/PROXIED are extracted – tokens and every
other value stay where they are and are never returned."""
from __future__ import annotations

import re
from pathlib import Path

from .config import settings
from .updater import HOST_RE

MAX_FILE = 256 * 1024
KEYS = ("IP4_DOMAINS", "IP6_DOMAINS", "DOMAINS", "PROXIED")
_KEY_RE = re.compile(
    r"""^\s*(?:-\s*)?["']?(IP4_DOMAINS|IP6_DOMAINS|DOMAINS|PROXIED)["']?\s*[=:]\s*(.*?)\s*$""", re.M)
_ENV_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", re.M)
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-?]([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _unquote(value: str) -> str:
    value = re.sub(r"\s+#.*$", "", value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value.strip().strip("'\"")


def _interpolate(value: str, env: dict[str, str]) -> str:
    def sub(m: re.Match) -> str:
        name = m.group(1) or m.group(3)
        return env.get(name) or (m.group(2) or "")
    return _VAR_RE.sub(sub, value)


def parse_texts(texts: list[str]) -> dict:
    env: dict[str, str] = {}
    for text in texts:
        for k, v in _ENV_RE.findall(text):
            if k not in KEYS:
                env.setdefault(k, _unquote(v))
    domains: dict[str, dict] = {}
    proxied: bool | None = None
    proxied_expr = None
    invalid = 0  # only counted: an unparsable value could be an interpolated secret
    for text in texts:
        for key, raw in _KEY_RE.findall(text):
            value = _interpolate(_unquote(raw), env)
            if key == "PROXIED":
                low = value.lower()
                if low in ("true", "false"):
                    proxied = low == "true"
                elif value:
                    proxied_expr = value
                continue
            for d in value.split(","):
                d = d.strip().lower().rstrip(".")
                if not d:
                    continue
                if not HOST_RE.match(d):
                    invalid += 1
                    continue
                e = domains.setdefault(d, {"ipv4": False, "ipv6": False})
                if key in ("DOMAINS", "IP4_DOMAINS"):
                    e["ipv4"] = True
                if key in ("DOMAINS", "IP6_DOMAINS"):
                    e["ipv6"] = True
    return {"domains": domains, "proxied_default": proxied, "proxied_expr": proxied_expr,
            "invalid": invalid}


def _candidate_files(root: Path) -> list[Path]:
    names = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", ".env")
    out: list[Path] = []
    for base in (root, *[p for p in sorted(root.iterdir()) if p.is_dir() and not p.is_symlink()][:20]):
        for p in sorted(base.iterdir()):
            if p.is_file() and not p.is_symlink() and (p.name in names or p.suffix == ".env"):
                out.append(p)
    return out


def scan_import_dir() -> dict:
    root = settings.import_dir
    if not root.is_dir():
        return {"available": False, "files": []}
    try:
        files = _candidate_files(root)
    except OSError:
        return {"available": False, "files": []}
    texts, used = [], []
    for p in files:
        try:
            if p.stat().st_size <= MAX_FILE:
                texts.append(p.read_text(encoding="utf-8", errors="replace"))
                used.append(str(p.relative_to(root)))
        except OSError:
            continue
    return {"available": True, "files": used, **parse_texts(texts)}
