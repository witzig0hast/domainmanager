"""Compare Cloudflare DNS with Nginx Proxy Manager to find subdomains nobody uses anymore."""
from __future__ import annotations

import asyncio
import socket
import time

from . import audit
from .cloudflare import cf
from .jsonstore import JsonStore
from .npm import NpmError, npm
from .updater import notify, store as ddns_store, updater

# status -> (label, counts as "unused")
STATUS = {
    "unused": ("Ungenutzt – zeigt auf dein Netz, aber kein NPM-Host", True),
    "backend_down": ("Backend nicht erreichbar", True),
    "disabled": ("NPM-Host deaktiviert", True),
    "dead_host": ("Nur 404-Host in NPM", True),
    "used": ("Genutzt", False),
    "external": ("Zeigt nicht auf dein Netz", False),
}

state = JsonStore("usage.json", {"report": None, "ignored": [], "notified": []})


def _covers(domain: str, name: str) -> bool:
    if domain == name:
        return True
    # NPM wildcard "*.example.org" matches exactly one extra label.
    return domain.startswith("*.") and name.endswith(domain[1:]) and name.count(".") == domain.count(".")


def _tcp_alive(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2.5):
            return True
    except OSError:
        return False


async def build_report(check_backends: bool = True) -> dict:
    records = await cf.all_records()
    npm_hosts: list[dict] = []
    npm_error = None
    try:
        npm_hosts = await npm.hosts(fresh=True)
    except NpmError as exc:
        npm_error = str(exc)

    home_ips = set(updater.state["ip"].values()) | set((ddns_store.data.get("last_ip") or {}).values())
    by_name: dict[str, list[dict]] = {}
    for r in records:
        if r["type"] in ("A", "AAAA", "CNAME") and not r["name"].split(".")[0].startswith("_"):
            by_name.setdefault(r["name"], []).append(r)

    def points_home(name: str, depth: int = 0) -> bool:
        if name in ddns_store.hosts:
            return True
        for r in by_name.get(name, []):
            if r["type"] in ("A", "AAAA") and r["content"] in home_ips:
                return True
            if r["type"] == "CNAME" and depth < 4 and points_home(r["content"].lower().rstrip("."), depth + 1):
                return True
        return False

    backend_alive: dict[tuple[str, int], bool] = {}
    if check_backends and not npm_error:
        targets = {(h["forward_host"], h["forward_port"]) for h in npm_hosts
                   if h["kind"] == "proxy" and h["enabled"] and h["forward_host"] and h["forward_port"]}
        sem = asyncio.Semaphore(10)

        async def probe(t):
            async with sem:
                backend_alive[t] = await asyncio.to_thread(_tcp_alive, *t)
        await asyncio.gather(*(probe(t) for t in targets))

    hosts = []
    for name, recs in sorted(by_name.items()):
        matches = [h for h in npm_hosts if any(_covers(d, name) for d in h["domains"])]
        enabled = [h for h in matches if h["enabled"]]
        home = points_home(name)
        if npm_error:
            status = "unknown"
        elif any(h["kind"] in ("proxy", "redirect") for h in enabled):
            proxies = [h for h in enabled if h["kind"] == "proxy"]
            if proxies and backend_alive and not any(
                    backend_alive.get((h["forward_host"], h["forward_port"]), True) for h in proxies):
                status = "backend_down"
            else:
                status = "used"
        elif enabled:
            status = "dead_host"
        elif matches:
            status = "disabled"
        elif home:
            status = "unused"
        else:
            status = "external"
        hosts.append({
            "name": name, "status": status, "home": home, "ddns": name in ddns_store.hosts,
            "records": [{"id": r["id"], "zone_id": r["zone_id"], "type": r["type"], "content": r["content"],
                         "proxied": r["proxied"]} for r in recs],
            "npm": [{"kind": h["kind"], "domains": h["domains"], "target": h["target"], "enabled": h["enabled"],
                     "ssl": h["ssl"], "access_list": h["access_list"],
                     "alive": backend_alive.get((h.get("forward_host"), h.get("forward_port")))} for h in matches],
        })

    # NPM hosts whose domain has no DNS record at Cloudflare (stale config or managed elsewhere).
    zones = [z["name"] for z in await cf.zones()]
    orphans = []
    for h in npm_hosts:
        for d in h["domains"]:
            in_zone = any(d == z or d.endswith("." + z) for z in zones)
            has_dns = d in by_name or any(_covers(n, d) for n in by_name if n.startswith("*."))
            if in_zone and not has_dns and not d.startswith("*."):
                orphans.append({"domain": d, "kind": h["kind"], "target": h["target"], "enabled": h["enabled"]})

    counts = {k: sum(1 for h in hosts if h["status"] == k) for k in (*STATUS, "unknown")}
    return {"generated": time.time(), "npm_configured": npm.configured, "npm_error": npm_error,
            "npm_hosts": len(npm_hosts), "hosts": hosts, "npm_orphans": orphans, "counts": counts}


async def refresh(notify_new: bool = True) -> dict:
    report = await build_report()
    state.data["report"] = report
    ignored = set(state.data["ignored"])
    unused = {h["name"] for h in report["hosts"] if STATUS.get(h["status"], ("", False))[1]}
    new = sorted(unused - ignored - set(state.data["notified"]))
    send = bool(new) and notify_new and not report["npm_error"]
    # Remember what was announced so a host is only reported once while it stays unused.
    state.data["notified"] = sorted(unused & (set(state.data["notified"]) | (set(new) if send else set())))
    await asyncio.to_thread(state.save)
    if send:
        audit.log("unused_subdomains_found", "", hosts=new)
        lines = [f"{n} ({STATUS[next(h['status'] for h in report['hosts'] if h['name'] == n)][0]})" for n in new[:15]]
        await notify("Ungenutzte Subdomains gefunden:\n" + "\n".join(lines)
                     + (f"\n… und {len(new) - 15} weitere" if len(new) > 15 else ""))
    return report
