"""Built-in dynamic DNS updater – replaces favonia/cloudflare-ddns.

The dashboard is the source of truth: on every run each managed host's A/AAAA record is
created or corrected (IP, proxy status, TTL) so it matches the settings made in the UI."""
from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import os
import re
import tempfile
import threading
import time

import httpx

from . import audit
from .cloudflare import CloudflareError, cf
from .config import settings

HOST_RE = re.compile(r"^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
RECORD_COMMENT = "DomainManager DDNS"
TTL_CHOICES = (1, 60, 120, 300, 600, 1800, 3600)
MAX_HISTORY = 100

# Same approach as favonia's default: Cloudflare's trace endpoint, with a fallback provider.
PROVIDERS = {
    4: ("https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace", "https://api4.ipify.org"),
    6: ("https://[2606:4700:4700::1111]/cdn-cgi/trace", "https://[2606:4700:4700::1001]/cdn-cgi/trace",
        "https://api6.ipify.org"),
}


class UpdaterError(Exception):
    pass


def normalize(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if len(host) > 253 or not HOST_RE.match(host):
        raise UpdaterError(f"Ungültiger Hostname: {host!r}")
    return host


# ------------------------------------------------------------------ persistent store

class Store:
    def __init__(self) -> None:
        self.path = settings.data_dir / "ddns.json"
        self._lock = threading.Lock()
        self.data = self._load()

    def _defaults(self) -> dict:
        return {"enabled": False, "interval": settings.ddns_interval, "ipv4": True,
                "ipv6": settings.ddns_ipv6, "hosts": {}, "history": [], "last_ip": {}}

    def _load(self) -> dict:
        data = self._defaults()
        try:
            data.update(json.loads(self.path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
        return data

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".ddns-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(self.data, fh, indent=1, ensure_ascii=False)
                os.replace(tmp, self.path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self.data)

    @property
    def hosts(self) -> dict[str, dict]:
        return self.data["hosts"]


store = Store()


def host_entry(ipv4: bool = True, ipv6: bool = False, proxied: bool = False, ttl: int = 1) -> dict:
    if not (ipv4 or ipv6):
        raise UpdaterError("Mindestens IPv4 oder IPv6 auswählen")
    if ttl not in TTL_CHOICES:
        raise UpdaterError("Ungültige TTL")
    return {"ipv4": bool(ipv4), "ipv6": bool(ipv6), "proxied": bool(proxied), "ttl": ttl,
            "enabled": True, "added": int(time.time())}


def managed_names() -> set[str]:
    return set(store.hosts)


# ------------------------------------------------------------------ IP detection

def _valid(raw: str, version: int) -> str | None:
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    return str(ip) if ip.version == version and ip.is_global else None


async def detect_ip(version: int) -> tuple[str | None, str]:
    errors = []
    async with httpx.AsyncClient(timeout=6.0, headers={"User-Agent": "DomainManager-DDNS/1.0"}) as client:
        for url in PROVIDERS[version]:
            try:
                r = await client.get(url)
                r.raise_for_status()
            except httpx.HTTPError as exc:
                errors.append(exc.__class__.__name__)
                continue
            text = r.text
            if "/cdn-cgi/trace" in url:
                text = next((line[3:] for line in text.splitlines() if line.startswith("ip=")), "")
            ip = _valid(text, version)
            if ip:
                return ip, url
            errors.append("ungültige Antwort")
    return None, ", ".join(dict.fromkeys(errors)) or "keine Antwort"


# ------------------------------------------------------------------ notifications

async def notify(text: str) -> None:
    url = settings.notify_url
    if not url:
        return
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            if "discord.com/api/webhooks" in url:
                await client.post(url, json={"content": text})
            else:  # ntfy / Gotify-compatible plain text
                await client.post(url, content=text.encode(), headers={"Title": "DomainManager"})
    except httpx.HTTPError as exc:
        print(f"notify failed: {exc!r}", flush=True)


# ------------------------------------------------------------------ updater loop

class Updater:
    def __init__(self) -> None:
        self.state: dict = {"ip": {}, "ip_error": {}, "ip_source": {}, "last_run": None, "next_run": None,
                            "running": False, "hosts": {}, "error": None}
        self._wake = asyncio.Event()
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    def trigger(self) -> None:
        self._wake.set()

    async def _loop(self) -> None:
        await asyncio.sleep(3)
        while True:
            if store.data["enabled"]:
                try:
                    await self.run_once()
                except Exception as exc:  # noqa: BLE001 – the loop must never die
                    print(f"ddns run failed: {exc!r}", flush=True)
                    self.state["error"] = "Interner Fehler – siehe Container-Log"
            interval = max(60, int(store.data.get("interval") or settings.ddns_interval))
            self.state["next_run"] = time.time() + interval if store.data["enabled"] else None
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass

    async def refresh_ips(self) -> None:
        for v in (4, 6):
            if not store.data.get(f"ipv{v}"):
                self.state["ip"].pop(v, None)
                self.state["ip_error"].pop(v, None)
                continue
            ip, info = await detect_ip(v)
            if ip:
                self.state["ip"][v] = ip
                self.state["ip_source"][v] = info
                self.state["ip_error"].pop(v, None)
            else:
                self.state["ip"].pop(v, None)
                self.state["ip_error"][v] = info

    async def run_once(self, reason: str = "auto") -> None:
        async with self._lock:
            self.state["running"] = True
            try:
                await self._run(reason)
            finally:
                self.state["running"] = False
                self.state["last_run"] = time.time()

    async def _run(self, reason: str) -> None:
        await self.refresh_ips()
        ips = self.state["ip"]
        await self._record_ip_changes(ips)
        self.state["error"] = None
        hosts = {n: h for n, h in store.hosts.items() if h.get("enabled", True)}
        if not hosts:
            return
        changed: list[str] = []
        records_by_zone: dict[str, list[dict]] = {}
        for name, h in sorted(hosts.items()):
            status = {"ts": time.time(), "ok": True, "msgs": []}
            self.state["hosts"][name] = status
            try:
                zone = await cf.zone_for(name)
                if zone is None:
                    raise UpdaterError("Keine passende Zone im Cloudflare-Konto")
                if zone["id"] not in records_by_zone:
                    cf.forget_records(zone["id"])
                    records_by_zone[zone["id"]] = await cf.records(zone["id"])
                recs = records_by_zone[zone["id"]]
                maintained = 0
                for v, rtype in ((4, "A"), (6, "AAAA")):
                    existing = [r for r in recs if r["name"] == name and r["type"] == rtype]
                    if not h.get(f"ipv{v}"):
                        continue
                    if not store.data.get(f"ipv{v}"):
                        if existing:  # a record that silently goes stale is worth mentioning
                            status["msgs"].append(f"{rtype} vorhanden, aber IPv{v} global aus")
                        continue
                    maintained += 1
                    ip = ips.get(v)
                    if not ip:
                        status["ok"] = False
                        status["msgs"].append(f"IPv{v} unbekannt – übersprungen")
                        continue
                    action = await self._sync_record(zone["id"], name, rtype, ip, h, existing)
                    if action:
                        changed.append(f"{rtype} {name} {action}")
                        status["msgs"].append(f"{rtype} {action}")
                    if len(existing) > 1:
                        status["msgs"].append(f"{len(existing)} {rtype}-Records – nur der erste wird gepflegt")
                if not maintained:
                    status["ok"] = False
                    status["msgs"].append("Nichts zu pflegen – benötigte IP-Version ist global deaktiviert")
                if not status["msgs"]:
                    status["msgs"].append("aktuell")
            except (CloudflareError, UpdaterError) as exc:
                status["ok"] = False
                status["msgs"].append(str(exc))
        if changed:
            audit.log("ddns_sync", "", reason=reason, changes=changed)
        failed = [n for n, s in self.state["hosts"].items() if n in hosts and not s["ok"]]
        if failed:
            self.state["error"] = f"{len(failed)} Host(s) mit Fehler"

    async def _sync_record(self, zone_id: str, name: str, rtype: str, ip: str, h: dict,
                           existing: list[dict]) -> str | None:
        proxied = bool(h.get("proxied"))
        ttl = int(h.get("ttl") or 1)
        if not existing:
            await cf.create_record(zone_id, rtype, name, ip, proxied, ttl, RECORD_COMMENT)
            return f"angelegt → {ip}"
        r = existing[0]
        patch: dict = {}
        if r["content"] != ip:
            patch["content"] = ip
        if r["proxied"] != proxied:
            patch["proxied"] = proxied
        want_ttl = 1 if proxied else ttl
        if r.get("ttl") != want_ttl:
            patch["ttl"] = want_ttl
        if not patch:
            return None
        await cf.update_record(zone_id, r["id"], **patch)
        parts = []
        if "content" in patch:
            parts.append(f"{r['content']} → {ip}")
        if "proxied" in patch:
            parts.append("Proxy an" if proxied else "Proxy aus")
        if "ttl" in patch and "proxied" not in patch:
            parts.append(f"TTL {want_ttl}")
        return "aktualisiert (" + ", ".join(parts) + ")"

    async def _record_ip_changes(self, ips: dict[int, str]) -> None:
        last = store.data.setdefault("last_ip", {})
        msgs = []
        changed = False
        for v, ip in ips.items():
            old = last.get(str(v))
            if ip != old:
                changed = True
                last[str(v)] = ip
                store.data["history"].insert(0, {"ts": int(time.time()), "version": v, "old": old, "new": ip})
                if old:
                    msgs.append(f"IPv{v}: {old} → {ip}")
        if not changed:
            return
        del store.data["history"][MAX_HISTORY:]
        await asyncio.to_thread(store.save)
        if msgs:
            audit.log("ip_changed", "", changes=msgs)
            await notify("Neue öffentliche IP – " + "; ".join(msgs))


updater = Updater()
