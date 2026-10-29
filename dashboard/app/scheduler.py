"""Background automation:
- rotating security scan: tests a few hosts per run so that every host is covered once per period
  (e.g. one week), then starts the next cycle;
- periodic NPM usage check with notification about newly unused subdomains."""
from __future__ import annotations

import asyncio
import math
import time
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import audit, ollama, usage
from .cloudflare import CloudflareError, cf
from .config import settings
from .jsonstore import JsonStore
from .npm import npm
from .scanner import SEVERITY_ORDER, run_scan, score
from .updater import notify

USAGE_INTERVAL = 6 * 3600

store = JsonStore("schedule.json", {
    "settings": {"enabled": False, "period_days": 7, "interval_hours": 6, "window_start": 0, "window_end": 24,
                 "ai": True, "model": "", "notify": True},
    "excluded": [],
    "cycle": {"started": None, "tested": {}, "completed": None},
    "results": {},          # host -> {ts, score, counts, findings}
    "zones": {},            # zone name -> {ts, findings}
    "last_run": None, "last_batch": [], "last_error": None,
    "summary": None,        # AI/summary of the last completed cycle
    "usage_last": None,
})


def _tz():
    try:
        return ZoneInfo(settings.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def in_window(cfg: dict, now: float | None = None) -> bool:
    start, end = int(cfg["window_start"]), int(cfg["window_end"])
    if start == 0 and end == 24:
        return True
    hour = datetime.fromtimestamp(now or time.time(), _tz()).hour
    return start <= hour < end if start < end else (hour >= start or hour < end)


async def scannable_hosts() -> list[str]:
    names = {r["name"] for r in await cf.all_records()
             if r["type"] in ("A", "AAAA", "CNAME") and not r["name"].startswith(("*.", "_"))}
    return sorted(names - set(store.data["excluded"]))


def plan(hosts: list[str], now: float | None = None) -> dict:
    """How many hosts the next run has to cover so the cycle finishes within the period."""
    now = now or time.time()
    cfg = store.data["settings"]
    cycle = store.data["cycle"]
    tested = {h for h, ts in cycle["tested"].items() if h in hosts}
    remaining = [h for h in hosts if h not in tested]
    started = cycle["started"] or now
    period = cfg["period_days"] * 86400
    interval = cfg["interval_hours"] * 3600
    window_share = 1.0 if (cfg["window_start"], cfg["window_end"]) == (0, 24) else \
        ((cfg["window_end"] - cfg["window_start"]) % 24 or 24) / 24
    runs_left = max(1, math.floor((started + period - now) / interval * window_share))
    batch = min(settings.max_scan_hosts, max(1, math.ceil(len(remaining) / runs_left))) if remaining else 0
    # Least recently scanned first, so hosts with stale results come next.
    remaining.sort(key=lambda h: (store.data["results"].get(h, {}).get("ts") or 0, h))
    return {"total": len(hosts), "tested": len(tested), "remaining": remaining, "batch": remaining[:batch],
            "runs_left": runs_left, "cycle_ends": started + period}


class Scheduler:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._wake = asyncio.Event()
        self.running = False
        self.progress = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    def trigger(self) -> None:
        self._wake.set()

    def next_run(self) -> float | None:
        cfg = store.data["settings"]
        if not cfg["enabled"]:
            return None
        return (store.data["last_run"] or 0) + cfg["interval_hours"] * 3600

    async def _loop(self) -> None:
        await asyncio.sleep(20)
        while True:
            try:
                await self._tick()
            except Exception as exc:  # noqa: BLE001 – keep the loop alive
                print(f"scheduler tick failed: {exc!r}", flush=True)
                store.data["last_error"] = "Interner Fehler – siehe Container-Log"
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=300)
            except asyncio.TimeoutError:
                pass

    async def _tick(self) -> None:
        now = time.time()
        if npm.configured and now - (store.data["usage_last"] or 0) > USAGE_INTERVAL:
            store.data["usage_last"] = now
            try:
                await usage.refresh()
            except CloudflareError as exc:
                print(f"usage refresh failed: {exc}", flush=True)
        cfg = store.data["settings"]
        if cfg["enabled"] and now >= (self.next_run() or 0) and in_window(cfg, now):
            await self.run_batch("auto")
        await asyncio.to_thread(store.save)

    async def run_batch(self, reason: str) -> dict:
        if self.running:
            return {"skipped": "läuft bereits"}
        self.running = True
        try:
            return await self._run_batch(reason)
        finally:
            self.running = False
            self.progress = None

    async def _run_batch(self, reason: str) -> dict:
        cycle = store.data["cycle"]
        period = store.data["settings"]["period_days"] * 86400
        if not cycle["started"] or (cycle["completed"] and time.time() >= cycle["started"] + period):
            cycle.update(started=time.time(), tested={}, completed=None)
        store.data["last_run"] = time.time()
        store.data["last_error"] = None
        try:
            hosts = await scannable_hosts()
        except CloudflareError as exc:
            store.data["last_error"] = str(exc)
            return {"error": str(exc)}
        p = plan(hosts)
        batch = p["batch"]
        store.data["last_batch"] = batch
        if batch:
            def progress(done: int, total: int) -> None:
                self.progress = {"done": done, "total": total, "hosts": batch}
            try:
                result = await run_scan(batch, progress)
            except CloudflareError as exc:
                store.data["last_error"] = str(exc)
                return {"error": str(exc)}
            await self._store_results(batch, result)
            audit.log("scheduled_scan", "", reason=reason, hosts=batch, score=result["score"])
        if not [h for h in hosts if h not in cycle["tested"]]:
            await self._complete_cycle(hosts)
        await asyncio.to_thread(store.save)
        return {"scanned": batch}

    async def _store_results(self, batch: list[str], result: dict) -> None:
        now = time.time()
        zone_names = {z["name"] for z in await cf.zones()}
        new_severe = []
        for host in batch:
            findings = [f for f in result["findings"] if f["host"] == host and not f.get("zone")]
            prev = store.data["results"].get(host, {})
            prev_titles = {f["title"] for f in prev.get("findings", []) if f["severity"] in ("critical", "high")}
            new_severe += [f"{host}: {f['title']}" for f in findings
                           if f["severity"] in ("critical", "high") and f["title"] not in prev_titles]
            store.data["results"][host] = {
                "ts": now, "score": score(findings), "findings": findings,
                "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}}
            store.data["cycle"]["tested"][host] = now
        for z in zone_names:
            zf = [f for f in result["findings"] if f["host"] == z and f.get("zone")]
            if zf:
                store.data["zones"][z] = {"ts": now, "findings": zf}
        if new_severe and store.data["settings"]["notify"]:
            await notify("Neue kritische/hohe Befunde im Wochen-Scan:\n" + "\n".join(new_severe[:15]))

    async def _complete_cycle(self, hosts: list[str]) -> None:
        cycle = store.data["cycle"]
        if cycle.get("completed"):
            return  # the next cycle starts once the period is over (see _run_batch)
        cycle["completed"] = time.time()
        agg = self.aggregate(hosts)
        summary = {"ts": time.time(), "score": agg["score"], "counts": agg["counts"], "hosts": len(hosts)}
        cfg = store.data["settings"]
        if cfg["ai"]:
            model = cfg["model"] or settings.ollama_model
            try:
                summary["ai"] = await ollama.analyze(agg, model)
            except ollama.OllamaError as exc:
                summary["ai_error"] = str(exc)
        store.data["summary"] = summary
        audit.log("scheduled_cycle_complete", "", hosts=len(hosts), score=agg["score"])
        if cfg["notify"]:
            c = agg["counts"]
            await notify(f"Wochen-Scan abgeschlossen: {len(hosts)} Hosts, Score {agg['score']}/100 – "
                         f"{c.get('critical', 0)} kritisch, {c.get('high', 0)} hoch, {c.get('medium', 0)} mittel.")

    def aggregate(self, hosts: list[str] | None = None) -> dict:
        res = store.data["results"]
        names = hosts if hosts is not None else sorted(res)
        findings = [f for h in names for f in res.get(h, {}).get("findings", [])]
        findings += [f for z in store.data["zones"].values() for f in z["findings"]]
        findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["host"]))
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
        return {"hosts": [h for h in names if h in res], "findings": findings, "counts": counts, "score": score(findings)}


scheduler = Scheduler()
