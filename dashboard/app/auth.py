"""Single-admin authentication: Argon2id password, optional TOTP, server-side sessions."""
from __future__ import annotations

import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import settings

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
    created: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


class SessionStore:
    """In-memory sessions: a container restart logs everyone out, which is intended."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, user: str, ip: str) -> Session:
        s = Session(token=secrets.token_urlsafe(32), csrf=secrets.token_urlsafe(32), user=user, ip=ip)
        with self._lock:
            # Single admin: a fresh login invalidates all older sessions.
            self._sessions = {s.token: s}
        return s

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        now = time.time()
        with self._lock:
            s = self._sessions.get(token)
            if s is None:
                return None
            if (now - s.last_seen > settings.session_idle_minutes * 60
                    or now - s.created > settings.session_max_hours * 3600):
                del self._sessions[token]
                return None
            s.last_seen = now
            return s

    def destroy(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(token, None)


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
