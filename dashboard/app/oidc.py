"""OpenID Connect login (tested against Authentik): authorization code flow with PKCE.

The ID token is received directly from the token endpoint over verified TLS, which OIDC Core
§3.1.3.7 allows as a substitute for checking its signature; issuer, audience, expiry and nonce
are still validated."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode

import httpx

from .config import settings

FLOW_TTL = 600


class OidcError(Exception):
    pass


_discovery: tuple[float, dict] | None = None
_pending: dict[str, dict] = {}


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=10.0, verify=settings.oidc_verify_tls)


async def discovery() -> dict:
    global _discovery
    if _discovery and time.time() - _discovery[0] < 3600:
        return _discovery[1]
    url = settings.oidc_issuer + "/.well-known/openid-configuration"
    try:
        async with _client() as c:
            r = await c.get(url)
            r.raise_for_status()
            doc = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError(f"SSO-Anbieter nicht erreichbar ({exc.__class__.__name__})") from exc
    if doc.get("issuer", "").rstrip("/") != settings.oidc_issuer:
        raise OidcError("Issuer des SSO-Anbieters passt nicht zu OIDC_ISSUER_URL")
    for key in ("authorization_endpoint", "token_endpoint"):
        if not str(doc.get(key, "")).startswith("https://") and settings.oidc_verify_tls:
            raise OidcError(f"{key} muss HTTPS verwenden")
    _discovery = (time.time(), doc)
    return doc


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


async def begin(redirect_uri: str) -> tuple[str, str]:
    """Returns (authorization URL, browser binding token for a short-lived cookie)."""
    doc = await discovery()
    now = time.time()
    for k in [k for k, v in _pending.items() if now - v["ts"] > FLOW_TTL]:
        del _pending[k]
    if len(_pending) > 100:
        raise OidcError("Zu viele offene Anmeldungen – bitte kurz warten")
    state, nonce, verifier, browser = (secrets.token_urlsafe(32) for _ in range(4))
    _pending[state] = {"nonce": nonce, "verifier": verifier, "browser": browser, "ts": now,
                       "redirect_uri": redirect_uri}
    query = urlencode({
        "response_type": "code", "client_id": settings.oidc_client_id, "redirect_uri": redirect_uri,
        "scope": "openid email profile", "state": state, "nonce": nonce,
        "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256",
    })
    return f"{doc['authorization_endpoint']}?{query}", browser


def _claims(id_token: str) -> dict:
    try:
        payload = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError) as exc:
        raise OidcError("Ungültiges ID-Token") from exc


async def complete(code: str, state: str, browser: str) -> dict:
    flow = _pending.pop(state, None)
    if flow is None or time.time() - flow["ts"] > FLOW_TTL:
        raise OidcError("Anmeldung abgelaufen – bitte erneut versuchen")
    if not secrets.compare_digest(flow["browser"], browser or ""):
        raise OidcError("Anmeldung wurde in einem anderen Browser gestartet")
    doc = await discovery()
    try:
        async with _client() as c:
            r = await c.post(doc["token_endpoint"], data={
                "grant_type": "authorization_code", "code": code, "redirect_uri": flow["redirect_uri"],
                "client_id": settings.oidc_client_id, "client_secret": settings.oidc_client_secret,
                "code_verifier": flow["verifier"]})
            if r.status_code != 200:
                raise OidcError("SSO-Anbieter hat den Code abgelehnt (Client-ID/Secret/Redirect-URI prüfen)")
            tokens = r.json()
            claims = _claims(tokens.get("id_token", ""))
            info = {}
            if doc.get("userinfo_endpoint") and tokens.get("access_token"):
                u = await c.get(doc["userinfo_endpoint"], headers={"Authorization": f"Bearer {tokens['access_token']}"})
                if u.status_code == 200:
                    info = u.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError(f"SSO-Anbieter nicht erreichbar ({exc.__class__.__name__})") from exc

    aud = claims.get("aud")
    if claims.get("iss", "").rstrip("/") != settings.oidc_issuer:
        raise OidcError("ID-Token: falscher Issuer")
    if settings.oidc_client_id not in (aud if isinstance(aud, list) else [aud]):
        raise OidcError("ID-Token: falsche Audience")
    if float(claims.get("exp", 0)) < time.time():
        raise OidcError("ID-Token abgelaufen")
    if not secrets.compare_digest(str(claims.get("nonce", "")), flow["nonce"]):
        raise OidcError("ID-Token: Nonce stimmt nicht")
    if info.get("sub") and info["sub"] != claims.get("sub"):
        raise OidcError("Userinfo gehört zu einem anderen Benutzer")

    merged = {**claims, **info}
    user = str(merged.get("preferred_username") or merged.get("email") or merged.get("sub"))
    email = str(merged.get("email") or "").lower()
    groups = [str(g) for g in (merged.get("groups") or [])]
    allowed = True
    if settings.oidc_allowed_groups or settings.oidc_allowed_users:
        allowed = bool(set(groups) & set(settings.oidc_allowed_groups)) or \
            user.lower() in settings.oidc_allowed_users or (email and email in settings.oidc_allowed_users)
    if not allowed:
        raise OidcError(f"{user} hat keinen Zugriff (Gruppe fehlt)")
    return {"user": user[:64], "email": email, "groups": groups}
