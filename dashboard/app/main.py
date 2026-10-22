"""DomainManager – FastAPI app: auth, Cloudflare DNS, DDNS domain list, security scans."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import audit, ddns, ollama
from .auth import SESSION_COOKIE, Session, limiter, sessions, verify_credentials
from .cloudflare import CloudflareError, cf, valid_id
from .config import settings
from .scanner import run_scan

STATIC = Path(__file__).parent / "static"
MAX_BODY = 64 * 1024
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")
SEC_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if not settings.admin_password_hash:
        print("WARNUNG: Kein ADMIN_PASSWORD_HASH gesetzt – Login ist deaktiviert.", flush=True)
    yield
    await cf.close()


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _ip_allowed(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in net for net in settings.allowed_networks)


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        return False
    return urlsplit(origin).netloc == request.headers.get("host", "")


@app.middleware("http")
async def guard(request: Request, call_next):
    ip = client_ip(request)
    if not _ip_allowed(ip):
        audit.log("blocked_ip", ip, path=request.url.path)
        resp = JSONResponse({"detail": "Forbidden"}, status_code=403)
    elif int(request.headers.get("content-length") or 0) > MAX_BODY:
        resp = JSONResponse({"detail": "Request zu groß"}, status_code=413)
    elif request.method not in SAFE_METHODS and not _same_origin(request):
        resp = JSONResponse({"detail": "Origin-Prüfung fehlgeschlagen"}, status_code=403)
    else:
        resp = await call_next(request)
    for k, v in SEC_HEADERS.items():
        resp.headers.setdefault(k, v)
    if settings.cookie_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


def require_session(request: Request) -> Session:
    s = sessions.get(request.cookies.get(SESSION_COOKIE))
    if s is None or s.ip != client_ip(request):
        raise HTTPException(401, "Nicht angemeldet")
    if request.method not in SAFE_METHODS:
        token = request.headers.get("x-csrf-token", "")
        if not secrets.compare_digest(token.encode(), s.csrf.encode()):
            raise HTTPException(403, "CSRF-Token ungültig")
    return s


@app.exception_handler(CloudflareError)
async def _cf_error(_req: Request, exc: CloudflareError):
    return JSONResponse({"detail": str(exc)}, status_code=exc.status)


@app.exception_handler(ddns.DdnsError)
async def _ddns_error(_req: Request, exc: ddns.DdnsError):
    return JSONResponse({"detail": str(exc)}, status_code=400)


@app.exception_handler(ollama.OllamaError)
async def _ollama_error(_req: Request, exc: ollama.OllamaError):
    return JSONResponse({"detail": str(exc)}, status_code=502)


# ---------------------------------------------------------------- auth

class LoginIn(BaseModel):
    user: str = Field(max_length=64)
    password: str = Field(max_length=256)
    otp: str = Field(default="", max_length=10)


@app.get("/api/session")
async def session_info(request: Request):
    s = sessions.get(request.cookies.get(SESSION_COOKIE))
    base = {"totp": bool(settings.totp_secret), "login_enabled": bool(settings.admin_password_hash)}
    if s is None or s.ip != client_ip(request):
        return {"authenticated": False, **base}
    return {
        "authenticated": True, "user": s.user, "csrf": s.csrf, **base,
        "allow_dns_delete": settings.allow_dns_delete,
        "applier_enabled": settings.applier_enabled,
        "default_model": settings.ollama_model,
        "max_scan_hosts": settings.max_scan_hosts,
    }


@app.post("/api/login")
async def login(body: LoginIn, request: Request):
    ip = client_ip(request)
    wait = limiter.blocked_for(ip)
    if wait:
        raise HTTPException(429, f"Zu viele Fehlversuche. Bitte {wait // 60 + 1} min warten.")
    ok = await asyncio.to_thread(verify_credentials, body.user, body.password, body.otp)
    if not ok:
        limiter.fail(ip)
        audit.log("login_failed", ip, user=body.user[:64])
        await asyncio.sleep(1)
        raise HTTPException(401, "Anmeldung fehlgeschlagen")
    limiter.success(ip)
    s = sessions.create(body.user, ip)
    audit.log("login", ip, user=body.user)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, s.token, httponly=True, secure=settings.cookie_secure,
                    samesite="strict", path="/", max_age=settings.session_max_hours * 3600)
    return resp


@app.post("/api/logout")
async def logout(request: Request, s: Session = Depends(require_session)):
    sessions.destroy(s.token)
    audit.log("logout", client_ip(request), user=s.user)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


# ---------------------------------------------------------------- status

@app.get("/api/status")
async def status(_s: Session = Depends(require_session)):
    out: dict = {"ddns": ddns.status(), "applier": ddns.applier_status()}
    try:
        out["cloudflare"] = {"ok": True, **await cf.verify()}
    except CloudflareError as exc:
        out["cloudflare"] = {"ok": False, "error": str(exc)}
    try:
        models = await ollama.models()
        out["ollama"] = {"ok": True, "url": settings.ollama_url, "models": len(models),
                         "default_model": settings.ollama_model,
                         "default_available": any(m["name"] == settings.ollama_model for m in models)}
    except ollama.OllamaError as exc:
        out["ollama"] = {"ok": False, "url": settings.ollama_url, "error": str(exc)}
    return out


# ---------------------------------------------------------------- cloudflare

def _check_id(value: str) -> str:
    if not valid_id(value):
        raise HTTPException(400, "Ungültige ID")
    return value


@app.get("/api/zones")
async def zones(_s: Session = Depends(require_session)):
    return await cf.zones()


@app.get("/api/zones/{zone_id}/records")
async def records(zone_id: str, refresh: bool = False, _s: Session = Depends(require_session)):
    _check_id(zone_id)
    if refresh:
        cf.invalidate()
    await cf.zone(zone_id)
    ddns_hosts = {d for v in ddns.read().values() for d in v}
    return [{**r, "in_ddns": r["type"] in ("A", "AAAA") and r["name"] in ddns_hosts} for r in await cf.records(zone_id)]


class DeleteIn(BaseModel):
    confirm: str = Field(max_length=255)


@app.delete("/api/zones/{zone_id}/records/{record_id}")
async def delete_record(zone_id: str, record_id: str, body: DeleteIn, request: Request,
                        s: Session = Depends(require_session)):
    if not settings.allow_dns_delete:
        raise HTTPException(403, "Löschen von DNS-Records ist deaktiviert (ALLOW_DNS_DELETE=false).")
    _check_id(zone_id), _check_id(record_id)
    rec = next((r for r in await cf.records(zone_id) if r["id"] == record_id), None)
    if rec is None:
        raise HTTPException(404, "Record nicht gefunden")
    if body.confirm.strip().lower() != rec["name"]:
        raise HTTPException(400, "Bestätigung stimmt nicht mit dem Record-Namen überein")
    await cf.delete_record(zone_id, record_id)
    audit.log("dns_record_deleted", client_ip(request), user=s.user, name=rec["name"],
              type=rec["type"], content=rec["content"])
    return {"ok": True}


# ---------------------------------------------------------------- ddns

@app.get("/api/ddns")
async def ddns_get(_s: Session = Depends(require_session)):
    domains = ddns.read()
    cf_error = None
    by_name: dict[str, list[dict]] = {}
    try:
        for r in await cf.all_records():
            if r["type"] in ("A", "AAAA"):
                by_name.setdefault(r["name"], []).append(
                    {"type": r["type"], "content": r["content"], "proxied": r["proxied"],
                     "zone_id": r["zone_id"], "id": r["id"]})
    except CloudflareError as exc:
        cf_error = str(exc)
    return {
        "status": ddns.status(),
        "applier": ddns.applier_status(),
        "cf_error": cf_error,
        "keys": {k: [{"name": d, "records": by_name.get(d, [])} for d in v] for k, v in domains.items()},
    }


class DdnsIn(BaseModel):
    domains: dict[str, list[str]]


@app.put("/api/ddns")
async def ddns_put(body: DdnsIn, request: Request, s: Session = Depends(require_session)):
    if sum(len(v) for v in body.domains.values()) > 500:
        raise HTTPException(400, "Zu viele Einträge")
    before = ddns.read()
    after = await asyncio.to_thread(ddns.write, body.domains)
    changes = {}
    for k in after:
        removed = sorted(set(before.get(k, [])) - set(after[k]))
        added = sorted(set(after[k]) - set(before.get(k, [])))
        if removed or added:
            changes[k] = {"removed": removed, "added": added}
    audit.log("ddns_updated", client_ip(request), user=s.user, changes=changes)
    return {"domains": after, "changes": changes}


@app.post("/api/ddns/apply")
async def ddns_apply(request: Request, s: Session = Depends(require_session)):
    nonce = await asyncio.to_thread(ddns.request_apply)
    audit.log("ddns_apply_requested", client_ip(request), user=s.user, nonce=nonce)
    return {"nonce": nonce}


@app.get("/api/ddns/apply")
async def ddns_apply_status(_s: Session = Depends(require_session)):
    return ddns.applier_status()


# ---------------------------------------------------------------- scans

_jobs: dict[str, dict] = {}
_tasks: set[asyncio.Task] = set()
HOST_RE = re.compile(r"^[a-z0-9*._-]{1,253}$")


@app.get("/api/ollama/models")
async def models(_s: Session = Depends(require_session)):
    return {"default": settings.ollama_model, "models": await ollama.models()}


class ScanIn(BaseModel):
    hosts: list[str] = Field(max_length=200)
    model: str = Field(default="", max_length=100)
    ai: bool = True


async def _run_job(job: dict, hosts: list[str], model: str, use_ai: bool) -> None:
    def progress(done: int, total: int) -> None:
        job["progress"] = {"done": done, "total": total}
    try:
        job["phase"] = "checks"
        job["result"] = await run_scan(hosts, progress)
        if use_ai:
            job["phase"] = "ai"
            try:
                job["ai"] = await ollama.analyze(job["result"], model)
            except ollama.OllamaError as exc:
                job["ai_error"] = str(exc)
        job["status"] = "done"
    except Exception as exc:  # noqa: BLE001 – surfaced to the UI, details in container log
        print(f"scan failed: {exc!r}", flush=True)
        job["status"] = "error"
        job["error"] = str(exc) if isinstance(exc, CloudflareError) else "Interner Fehler beim Scan"
    finally:
        job["finished"] = time.time()


@app.post("/api/scan")
async def scan_start(body: ScanIn, request: Request, s: Session = Depends(require_session)):
    hosts = sorted({h.strip().lower() for h in body.hosts if HOST_RE.match(h.strip().lower())})
    if not hosts:
        raise HTTPException(400, "Keine Hosts ausgewählt")
    if len(hosts) > settings.max_scan_hosts:
        raise HTTPException(400, f"Maximal {settings.max_scan_hosts} Hosts pro Scan")
    # Only names that exist in the account's zones may be probed (no arbitrary targets).
    known = {r["name"] for r in await cf.all_records()}
    unknown = [h for h in hosts if h not in known]
    if unknown:
        raise HTTPException(400, f"Nicht in deinen Zonen: {', '.join(unknown[:5])}")
    model = body.model or settings.ollama_model
    if body.ai:
        available = {m["name"]: m for m in await ollama.models()}
        if model not in available or not available[model]["usable"]:
            raise HTTPException(400, "Modell nicht verfügbar oder zu groß (OLLAMA_MAX_MODEL_GB)")
    if any(j["status"] == "running" for j in _jobs.values()):
        raise HTTPException(409, "Es läuft bereits ein Scan")
    for jid in sorted(_jobs, key=lambda k: _jobs[k]["started"])[:-10]:
        del _jobs[jid]
    jid = secrets.token_hex(8)
    job = {"id": jid, "status": "running", "phase": "start", "started": time.time(),
           "progress": {"done": 0, "total": len(hosts)}, "model": model if body.ai else None}
    _jobs[jid] = job
    task = asyncio.create_task(_run_job(job, hosts, model, body.ai))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    audit.log("scan_started", client_ip(request), user=s.user, hosts=hosts, model=job["model"])
    return {"id": jid}


@app.get("/api/scan/{job_id}")
async def scan_get(job_id: str, _s: Session = Depends(require_session)):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "Scan nicht gefunden")
    return job


@app.get("/api/scans")
async def scan_list(_s: Session = Depends(require_session)):
    return sorted(
        ({"id": j["id"], "status": j["status"], "started": j["started"],
          "hosts": len((j.get("result") or {}).get("hosts", [])),
          "score": (j.get("result") or {}).get("score")} for j in _jobs.values()),
        key=lambda j: -j["started"])


# ---------------------------------------------------------------- audit + static

@app.get("/api/audit")
async def audit_log(_s: Session = Depends(require_session)):
    return audit.tail(300)


@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"ok": True}


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC / "index.html")
