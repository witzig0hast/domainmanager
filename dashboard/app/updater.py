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
    4: ("https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace", "https://api4.ipify.org",
        "https://ipv4.icanhazip.com"),
    6: ("https://[2606:4700:4700::1111]/cdn-cgi/trace", "https://[2606:4700:4700::1001]/cdn-cgi/trace",
        "https://api6.ipify.org", "https://ipv6.icanhazip.com"),
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


async def probe_provider(client: httpx.AsyncClient, url: str, version: int) -> tuple[str | None, str]:
    try:
        r = await client.get(url)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        return None, f"{exc.__class__.__name__}: {str(exc)[:120]}"
    text = r.text
    if "/cdn-cgi/trace" in url:
        text = next((line[3:] for line in text.splitlines() if line.startswith("ip=")), "")
    ip = _valid(text, version)
    return (ip, "ok") if ip else (None, f"keine gültige öffentliche IPv{version} in der Antwort ({text.strip()[:40]!r})")


def _ip_client() -> httpx.AsyncClient:
    # trust_env=False: a proxy configured for the container must not change which IP we see.
    return httpx.AsyncClient(timeout=6.0, trust_env=False, headers={"User-Agent": "DomainManager-DDNS/1.0"})


async def detect_ip(version: int) -> tuple[str | None, str]:
    errors = []
    async with _ip_client() as client:
        for url in PROVIDERS[version]:
            ip, info = await probe_provider(client, url, version)
            if ip:
                return ip, url
            errors.append(f"{url.split('/')[2]}: {info}")
    return None, " | ".join(errors) or "keine Antwort"


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
                            "running": False, "hosts": {}, "error": None, "log": [], "loop_alive": None,
                            "loop_error": None}
        self._wake = asyncio.Event()
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())
        self._task.add_done_callback(self._loop_ended)

    def _loop_ended(self, task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        self.state["loop_error"] = repr(exc)
        print(f"DDNS: Hintergrund-Schleife beendet: {exc!r}", flush=True)

    def ensure_running(self) -> None:
        """Watchdog: restart the loop if it died for any reason."""
        if self._task is None or self._task.done():
            print("DDNS: Schleife lief nicht – starte neu", flush=True)
            self.start()

    def health(self) -> str:
        if not store.data["enabled"]:
            return "paused"
        if not any(h.get("enabled", True) for h in store.hosts.values()):
            return "no_hosts"
        interval = max(60, int(store.data.get("interval") or settings.ddns_interval))
        last = self.state["last_run"]
        if self._task is None or self._task.done() or (last and time.time() - last > 2 * interval + 120):
            return "stalled"
        if self.state["error"] or self.state["ip_error"]:
            return "error"
        return "ok" if last else "starting"

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    def trigger(self) -> None:
        self._wake.set()

    async def _loop(self) -> None:
        await asyncio.sleep(3)
        print("DDNS: Updater gestartet", flush=True)
        while True:
            self.state["loop_alive"] = time.time()
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
            self._entry = {"ts": time.time(), "reason": reason, "ip": {}, "changes": [], "errors": [], "unchanged": 0}
            try:
                await self._run(reason)
            except Exception as exc:
                self._entry["errors"].append(f"Interner Fehler: {exc!r}")
                raise
            finally:
                self.state["running"] = False
                self.state["last_run"] = time.time()
                self._finish_entry()

    def _finish_entry(self) -> None:
        e = self._entry
        e["ip"] = {str(k): v for k, v in self.state["ip"].items()}
        for v, err in self.state["ip_error"].items():
            e["errors"].append(f"IPv{v} nicht ermittelbar: {err}")
        self.state["log"] = ([e] + self.state["log"])[:50]
        ips = ", ".join(f"IPv{k}={v}" for k, v in e["ip"].items()) or "keine IP"
        print(f"DDNS [{e['reason']}]: {ips}; {len(e['changes'])} geändert, {e['unchanged']} aktuell, "
              f"{len(e['errors'])} Fehler" + "".join(f"\n  - {x}" for x in e["changes"] + e["errors"]), flush=True)

    async def _run(self, reason: str) -> None:
        await self.refresh_ips()
        ips = self.state["ip"]
        await self._record_ip_changes(ips)
        self.state["error"] = None
        hosts = {n: h for n, h in store.hosts.items() if h.get("enabled", True)}
        if not hosts:
            self._entry["errors"].append("Keine aktiven Hosts – nichts zu tun (DDNS → Importieren/Hinzufügen)")
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
                if maintained and not any("angelegt" in m or "aktualisiert" in m for m in status["msgs"]) and status["ok"]:
                    self._entry["unchanged"] += 1
                if not maintained:
                    status["ok"] = False
                    status["msgs"].append("Nichts zu pflegen – benötigte IP-Version ist global deaktiviert")
                if not status["msgs"]:
                    status["msgs"].append("aktuell")
            except (CloudflareError, UpdaterError) as exc:
                status["ok"] = False
                hint = " → API-Token braucht „Zone → DNS → Edit“" if getattr(exc, "status", 0) == 403 else ""
                status["msgs"].append(str(exc) + hint)
            if not status["ok"]:
                self._entry["errors"].append(f"{name}: {' · '.join(status['msgs'])}")
        self._entry["changes"] = changed
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


    async def diagnose(self) -> dict:
        """Check every IP provider and the Cloudflare token, including a no-op write test."""
        out: dict = {"providers": [], "cloudflare": {}, "write_test": None}
        async with _ip_client() as client:
            for v in (4, 6):
                for url in PROVIDERS[v]:
                    ip, info = await probe_provider(client, url, v)
                    out["providers"].append({"version": v, "url": url, "ip": ip, "info": info})
        try:
            out["cloudflare"] = {"ok": True, **await cf.verify()}
            zones = await cf.zones()
            out["cloudflare"]["zones"] = [z["name"] for z in zones]
        except CloudflareError as exc:
            out["cloudflare"] = {"ok": False, "error": str(exc)}
            return out
        # Re-save an existing record with identical content: proves 'DNS: Edit' without changing anything.
        for name in sorted(store.hosts):
            zone = await cf.zone_for(name)
            if not zone:
                continue
            cf.forget_records(zone["id"])
            rec = next((r for r in await cf.records(zone["id"]) if r["name"] == name and r["type"] in ("A", "AAAA")), None)
            if rec:
                try:
                    await cf.update_record(zone["id"], rec["id"], content=rec["content"])
                    out["write_test"] = {"ok": True, "record": f"{rec['type']} {name}"}
                except CloudflareError as exc:
                    out["write_test"] = {"ok": False, "record": f"{rec['type']} {name}", "error": str(exc)}
                break
        return out


updater = Updater()
