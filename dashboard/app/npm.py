"""Read-only client for Nginx Proxy Manager (proxy, redirection and 404 hosts)."""
from __future__ import annotations

import time

import httpx

from .config import settings


class NpmError(Exception):
    pass


class Npm:
    CACHE_TTL = 60

    def __init__(self) -> None:
        self._token: str | None = None
        self._token_exp = 0.0
        self._cache: tuple[float, list[dict]] | None = None

    @property
    def configured(self) -> bool:
        return bool(settings.npm_url and settings.npm_email and settings.npm_password)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=settings.npm_url, timeout=10.0, verify=settings.npm_verify_tls)

    async def _login(self, client: httpx.AsyncClient) -> None:
        try:
            r = await client.post("/api/tokens", json={"identity": settings.npm_email, "secret": settings.npm_password})
        except httpx.HTTPError as exc:
            raise NpmError(f"NPM nicht erreichbar ({exc.__class__.__name__})") from exc
        if r.status_code != 200:
            raise NpmError("NPM-Anmeldung fehlgeschlagen – E-Mail/Passwort prüfen")
        try:
            body = r.json()
        except ValueError as exc:
            raise NpmError("Ungültige Antwort von NPM") from exc
        if body.get("requires_2fa"):
            raise NpmError("Der NPM-Benutzer hat 2FA aktiv – bitte einen eigenen Lese-Benutzer ohne 2FA anlegen")
        self._token = body.get("token")
        if not self._token:
            raise NpmError("NPM lieferte kein Token")
        self._token_exp = time.time() + 6 * 3600  # NPM tokens last 1 day; renew early

    async def _get(self, client: httpx.AsyncClient, path: str) -> list[dict]:
        for attempt in (1, 2):
            if not self._token or time.time() > self._token_exp:
                await self._login(client)
            try:
                r = await client.get(path, headers={"Authorization": f"Bearer {self._token}"})
            except httpx.HTTPError as exc:
                raise NpmError(f"NPM nicht erreichbar ({exc.__class__.__name__})") from exc
            if r.status_code == 401 and attempt == 1:
                self._token = None
                continue
            if r.status_code == 403:
                raise NpmError(f"NPM-Benutzer darf {path} nicht lesen (Berechtigung 'View' vergeben)")
            if r.status_code != 200:
                raise NpmError(f"NPM-Fehler HTTP {r.status_code} bei {path}")
            try:
                data = r.json()
            except ValueError as exc:
                raise NpmError("Ungültige Antwort von NPM") from exc
            return data if isinstance(data, list) else []
        raise NpmError("NPM-Anmeldung fehlgeschlagen")

    async def hosts(self, fresh: bool = False) -> list[dict]:
        if not self.configured:
            raise NpmError("Nginx Proxy Manager ist nicht konfiguriert (NPM_URL, NPM_EMAIL, NPM_PASSWORD)")
        if not fresh and self._cache and time.time() - self._cache[0] < self.CACHE_TTL:
            return self._cache[1]
        out: list[dict] = []
        async with self._client() as client:
            for h in await self._get(client, "/api/nginx/proxy-hosts"):
                out.append({
                    "kind": "proxy", "id": h.get("id"), "domains": [d.lower() for d in h.get("domain_names") or []],
                    "enabled": bool(h.get("enabled", 1)),
                    "forward_host": str(h.get("forward_host") or ""), "forward_port": int(h.get("forward_port") or 0),
                    "target": f"{h.get('forward_scheme', 'http')}://{h.get('forward_host')}:{h.get('forward_port')}",
                    "ssl": bool(h.get("certificate_id")), "access_list": bool(h.get("access_list_id")),
                })
            for h in await self._get(client, "/api/nginx/redirection-hosts"):
                out.append({
                    "kind": "redirect", "id": h.get("id"), "domains": [d.lower() for d in h.get("domain_names") or []],
                    "enabled": bool(h.get("enabled", 1)),
                    "target": f"→ {h.get('forward_scheme', 'auto')}://{h.get('forward_domain_name')}",
                    "ssl": bool(h.get("certificate_id")), "access_list": False,
                })
            for h in await self._get(client, "/api/nginx/dead-hosts"):
                out.append({
                    "kind": "dead", "id": h.get("id"), "domains": [d.lower() for d in h.get("domain_names") or []],
                    "enabled": bool(h.get("enabled", 1)), "target": "404-Host",
                    "ssl": bool(h.get("certificate_id")), "access_list": False,
                })
        self._cache = (time.time(), out)
        return out


npm = Npm()
