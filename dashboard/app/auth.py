"""Authentication: Argon2id password with optional TOTP (or SSO, see oidc.py) and persistent server-side sessions."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import settings
from .jsonstore import JsonStore

_hasher = PasswordHasher()
# Verified against when the username is wrong so timing doesn't reveal it.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))

SESSION_COOKIE = "dm_session"


@dataclass
class Session:
    token: str
    csrf: str
    user: str
    ip: str
    method: str = "password"
    agent: str = ""
    created: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


def _key(token: str) -> str:
    # Only a hash of the token is stored on disk, so a leaked sessions.json can't be replayed.
    return hashlib.sha256(token.encode()).hexdigest()


class SessionStore:
    """Server-side sessions, persisted in /data so a container restart doesn't log anyone out."""

    MAX_SESSIONS = 20
    PERSIST_EVERY = 120  # seconds between last_seen writes

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store = JsonStore("sessions.json", {"sessions": {}})
        self._sessions: dict[str, dict] = self._store.data["sessions"]
        self._last_persist = 0.0
        self._prune(time.time())

    def _expired(self, s: dict, now: float) -> bool:
        return (now - s["last_seen"] > settings.session_idle_minutes * 60
                or now - s["created"] > settings.session_max_hours * 3600)

    def _prune(self, now: float) -> None:
        for k in [k for k, s in self._sessions.items() if self._expired(s, now)]:
            del self._sessions[k]

    def _persist(self) -> None:
        self._last_persist = time.time()
        try:
            self._store.save()
        except OSError as exc:
            print(f"sessions not persisted: {exc!r}", flush=True)

    def create(self, user: str, ip: str, method: str = "password", agent: str = "") -> Session:
        s = Session(token=secrets.token_urlsafe(32), csrf=secrets.token_urlsafe(32), user=user, ip=ip,
                    method=method, agent=agent[:120])
        with self._lock:
            now = time.time()
            self._prune(now)
            while len(self._sessions) >= self.MAX_SESSIONS:
                oldest = min(self._sessions, key=lambda k: self._sessions[k]["last_seen"])
                del self._sessions[oldest]
            data = {k: v for k, v in s.__dict__.items() if k != "token"}
            self._sessions[_key(s.token)] = data
            self._persist()
        return s

    def get(self, token: str | None, ip: str) -> Session | None:
        if not token:
            return None
        now = time.time()
        with self._lock:
            key = _key(token)
            data = self._sessions.get(key)
            if data is None:
                return None
            if self._expired(data, now):
                del self._sessions[key]
                self._persist()
                return None
            if settings.session_bind_ip and data["ip"] != ip:
                return None
            data["last_seen"] = now
            data["ip"] = ip
            if now - self._last_persist > self.PERSIST_EVERY:
                self._persist()
            return Session(token=token, **data)

    def destroy(self, token: str | None) -> None:
        if token:
            with self._lock:
                if self._sessions.pop(_key(token), None) is not None:
                    self._persist()

    def list(self, current: str | None) -> list[dict]:
        cur = _key(current) if current else None
        with self._lock:
            return sorted(({"id": k[:12], "current": k == cur, **{f: v[f] for f in
                            ("user", "ip", "method", "agent", "created", "last_seen")}}
                           for k, v in self._sessions.items()), key=lambda x: -x["last_seen"])

    def destroy_others(self, current: str) -> int:
        cur = _key(current)
        with self._lock:
            others = [k for k in self._sessions if k != cur]
            for k in others:
                del self._sessions[k]
            self._persist()
            return len(others)


sessions = SessionStore()


class LoginLimiter:
    """Locks an IP out after repeated failures; also caps global failures to slow distributed guessing."""

    MAX_FAILS = 5
    WINDOW = 15 * 60
    LOCKOUT = 15 * 60
    GLOBAL_MAX = 30

    def __init__(self) -> None:
        self._fails: dict[str, list[float]] = {}
        self._locked: dict[str, float] = {}
        self._global: list[float] = []
        self._lock = threading.Lock()

    def blocked_for(self, ip: str) -> int:
        now = time.time()
        with self._lock:
            until = self._locked.get(ip, 0)
            if until > now:
                return int(until - now)
            self._global = [t for t in self._global if now - t < self.WINDOW]
            if len(self._global) >= self.GLOBAL_MAX:
                return int(self.WINDOW - (now - self._global[0]))
            return 0

    def fail(self, ip: str) -> None:
        now = time.time()
        with self._lock:
            fails = [t for t in self._fails.get(ip, []) if now - t < self.WINDOW] + [now]
            self._fails[ip] = fails
            self._global.append(now)
            if len(fails) >= self.MAX_FAILS:
                self._locked[ip] = now + self.LOCKOUT
                self._fails[ip] = []

    def success(self, ip: str) -> None:
        with self._lock:
            self._fails.pop(ip, None)
            self._locked.pop(ip, None)


limiter = LoginLimiter()
_used_totp: dict[str, float] = {}


def verify_credentials(user: str, password: str, otp: str) -> bool:
    if not settings.admin_password_hash:
        return False
    user_ok = hmac.compare_digest(user.encode(), settings.admin_user.encode())
    try:
        pw_ok = _hasher.verify(settings.admin_password_hash if user_ok else _DUMMY_HASH, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        pw_ok = False
    otp_ok = True
    if settings.totp_secret:
        otp = otp.replace(" ", "")
        otp_ok = bool(otp) and pyotp.TOTP(settings.totp_secret).verify(otp, valid_window=1)
        if otp_ok:
            # Reject replay of the same code within its validity window.
            now = time.time()
            for k in [k for k, t in _used_totp.items() if now - t > 120]:
                del _used_totp[k]
            if otp in _used_totp:
                otp_ok = False
            else:
                _used_totp[otp] = now
    return user_ok and pw_ok and otp_ok


def hash_password(password: str) -> str:
    return _hasher.hash(password)
