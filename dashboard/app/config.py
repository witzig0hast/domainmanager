"""Configuration, read once at startup from environment variables and Docker secrets."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = _env(name)
    return int(raw) if raw else default


def _secret(name: str) -> str:
    """Read NAME_FILE (preferred, Docker secret) or fall back to NAME."""
    path = _env(f"{name}_FILE")
    if path:
        p = Path(path)
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
        return ""
    return _env(name)


def _networks(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return nets


DEFAULT_ALLOWED = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10"


@dataclass(frozen=True)
class Settings:
    admin_user: str = field(default_factory=lambda: _env("ADMIN_USER", "admin"))
    admin_password_hash: str = field(default_factory=lambda: _secret("ADMIN_PASSWORD_HASH"))
    totp_secret: str = field(default_factory=lambda: _secret("TOTP_SECRET"))

    cf_api_token: str = field(default_factory=lambda: _secret("CF_API_TOKEN"))
    cf_api_key: str = field(default_factory=lambda: _secret("CF_API_KEY"))
    cf_api_email: str = field(default_factory=lambda: _env("CF_API_EMAIL"))

    ollama_url: str = field(default_factory=lambda: _env("OLLAMA_URL", "http://ollama:11434").rstrip("/"))
    ollama_model: str = field(default_factory=lambda: _env("OLLAMA_MODEL", "qwen2.5:7b-instruct"))
    ollama_num_ctx: int = field(default_factory=lambda: _int("OLLAMA_NUM_CTX", 8192))
    ollama_keep_alive: str = field(default_factory=lambda: _env("OLLAMA_KEEP_ALIVE", "2m"))
    ollama_max_model_gb: float = field(default_factory=lambda: float(_env("OLLAMA_MAX_MODEL_GB", "10")))

    ddns_interval: int = field(default_factory=lambda: max(60, _int("DDNS_INTERVAL", 300)))
    ddns_ipv6: bool = field(default_factory=lambda: _bool("DDNS_IPV6", False))
    import_dir: Path = field(default_factory=lambda: Path(_env("IMPORT_DIR", "/import")))
    notify_url: str = field(default_factory=lambda: _secret("NOTIFY_URL"))

    allow_dns_delete: bool = field(default_factory=lambda: _bool("ALLOW_DNS_DELETE", False))
    allowed_networks: list = field(default_factory=lambda: _networks(_env("ALLOWED_NETWORKS", DEFAULT_ALLOWED)))

    cookie_secure: bool = field(default_factory=lambda: _bool("COOKIE_SECURE", True))
    session_idle_minutes: int = field(default_factory=lambda: _int("SESSION_IDLE_MINUTES", 30))
    session_max_hours: int = field(default_factory=lambda: _int("SESSION_MAX_HOURS", 8))

    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", "/data")))
    max_scan_hosts: int = field(default_factory=lambda: _int("MAX_SCAN_HOSTS", 25))

    @property
    def cf_configured(self) -> bool:
        return bool(self.cf_api_token or (self.cf_api_key and self.cf_api_email))


settings = Settings()
