"""Minimal async Cloudflare API v4 client (zones, DNS records, zone settings)."""
from __future__ import annotations

import re
import time

import httpx

from .config import settings

API = "https://api.cloudflare.com/client/v4"
_ID_RE = re.compile(r"^[a-f0-9]{32}$")


class CloudflareError(Exception):
    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


def valid_id(value: str) -> bool:
    return bool(_ID_RE.match(value))


class Cloudflare:
    CACHE_TTL = 60

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._cache: dict[str, tuple[float, object]] = {}

    def _headers(self) -> dict[str, str]:
        if settings.cf_api_token:
            return {"Authorization": f"Bearer {settings.cf_api_token}"}
        return {"X-Auth-Key": settings.cf_api_key, "X-Auth-Email": settings.cf_api_email}

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=API, headers=self._headers(), timeout=20.0)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    def invalidate(self) -> None:
        self._cache.clear()

    async def _request(self, method: str, path: str, **kw) -> dict:
        if not settings.cf_configured:
            raise CloudflareError("Cloudflare API-Token ist nicht konfiguriert.", 503)
        try:
            resp = await self.client.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise CloudflareError(f"Cloudflare nicht erreichbar: {exc.__class__.__name__}") from exc
        try:
            body = resp.json()
        except ValueError:
            raise CloudflareError(f"Ungültige Antwort von Cloudflare (HTTP {resp.status_code})")
        if not body.get("success", False):
            errors = body.get("errors") or []
            msg = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errors) or f"HTTP {resp.status_code}"
            status = 403 if resp.status_code in (401, 403) else 502
            raise CloudflareError(f"Cloudflare-Fehler: {msg}", status)
        return body

    async def _paged(self, path: str, params: dict | None = None) -> list[dict]:
        out: list[dict] = []
        page = 1
        while True:
            body = await self._request("GET", path, params={**(params or {}), "page": page, "per_page": 100})
            out.extend(body.get("result") or [])
            info = body.get("result_info") or {}
            if page >= int(info.get("total_pages") or 1):
                return out
            page += 1

    async def _cached(self, key: str, loader):
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < self.CACHE_TTL:
            return hit[1]
        value = await loader()
        self._cache[key] = (time.time(), value)
        return value

    async def verify(self) -> dict:
        if settings.cf_api_token:
            body = await self._request("GET", "/user/tokens/verify")
            return {"type": "token", "status": body["result"].get("status")}
        await self._request("GET", "/user")
        return {"type": "global_key", "status": "active"}

    async def zones(self) -> list[dict]:
        async def load():
            raw = await self._paged("/zones")
            return [
                {
                    "id": z["id"],
                    "name": z["name"],
                    "status": z.get("status"),
                    "plan": (z.get("plan") or {}).get("name"),
                    "name_servers": z.get("name_servers") or [],
                    "paused": z.get("paused", False),
                }
                for z in raw
            ]
        return await self._cached("zones", load)

    async def zone(self, zone_id: str) -> dict:
        for z in await self.zones():
            if z["id"] == zone_id:
                return z
        raise CloudflareError("Zone nicht gefunden.", 404)

    async def records(self, zone_id: str) -> list[dict]:
        async def load():
            raw = await self._paged(f"/zones/{zone_id}/dns_records")
            return [
                {
                    "id": r["id"],
                    "type": r["type"],
                    "name": r["name"],
                    "content": r.get("content", ""),
                    "proxied": bool(r.get("proxied")),
                    "proxiable": bool(r.get("proxiable")),
                    "ttl": r.get("ttl"),
                    "comment": r.get("comment") or "",
                    "modified_on": r.get("modified_on"),
                }
                for r in raw
            ]
        return await self._cached(f"records:{zone_id}", load)

    async def all_records(self) -> list[dict]:
        out = []
        for z in await self.zones():
            for r in await self.records(z["id"]):
                out.append({**r, "zone_id": z["id"], "zone_name": z["name"]})
        return out

    def forget_records(self, zone_id: str) -> None:
        self._cache.pop(f"records:{zone_id}", None)

    async def create_record(self, zone_id: str, rtype: str, name: str, content: str,
                            proxied: bool, ttl: int, comment: str = "") -> dict:
        body = {"type": rtype, "name": name, "content": content, "proxied": proxied,
                "ttl": 1 if proxied else ttl, "comment": comment}
        res = await self._request("POST", f"/zones/{zone_id}/dns_records", json=body)
        self.forget_records(zone_id)
        return res["result"]

    async def update_record(self, zone_id: str, record_id: str, **fields) -> dict:
        res = await self._request("PATCH", f"/zones/{zone_id}/dns_records/{record_id}", json=fields)
        self.forget_records(zone_id)
        return res["result"]

    async def zone_for(self, name: str) -> dict | None:
        """The zone a hostname belongs to (longest matching suffix)."""
        bare = name[2:] if name.startswith("*.") else name
        best = None
        for z in await self.zones():
            if bare == z["name"] or bare.endswith("." + z["name"]):
                if best is None or len(z["name"]) > len(best["name"]):
                    best = z
        return best

    async def delete_record(self, zone_id: str, record_id: str) -> None:
        await self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
        self._cache.pop(f"records:{zone_id}", None)

    async def zone_settings(self, zone_id: str) -> dict[str, object] | None:
        """Returns None if the token lacks 'Zone Settings: Read'."""
        try:
            body = await self._request("GET", f"/zones/{zone_id}/settings")
        except CloudflareError as exc:
            if exc.status == 403:
                return None
            raise
        return {s["id"]: s.get("value") for s in body.get("result") or []}

    async def dnssec(self, zone_id: str) -> str | None:
        try:
            body = await self._request("GET", f"/zones/{zone_id}/dnssec")
        except CloudflareError:
            return None
        return (body.get("result") or {}).get("status")


cf = Cloudflare()
