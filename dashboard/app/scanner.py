"""Deterministic security checks. The LLM only explains these results, it never decides them."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone

import httpx

from .updater import managed_names
from .cloudflare import cf

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "ok"]
_WEIGHT = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0, "ok": 0}

SECURITY_HEADERS = {
    "strict-transport-security": ("medium", "HSTS fehlt", "Browser dürfen die Seite noch per HTTP laden (SSL-Stripping möglich)."),
    "content-security-policy": ("low", "Content-Security-Policy fehlt", "Ohne CSP ist XSS-Schaden deutlich größer."),
    "x-content-type-options": ("low", "X-Content-Type-Options fehlt", "Sollte 'nosniff' sein."),
    "referrer-policy": ("info", "Referrer-Policy fehlt", "Empfohlen: 'strict-origin-when-cross-origin' oder strenger."),
}


def _f(host: str, check: str, severity: str, title: str, detail: str = "") -> dict:
    return {"host": host, "check": check, "severity": severity, "title": title, "detail": detail}


def _is_private(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _tls_probe(host: str) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                return {"ok": True, "version": tls.version(), "not_after": cert.get("notAfter"),
                        "issuer": dict(x[0] for x in cert.get("issuer", ()))}
    except ssl.SSLCertVerificationError as exc:
        return {"ok": False, "reachable": True, "error": exc.verify_message or str(exc)}
    except (OSError, ssl.SSLError) as exc:
        return {"ok": False, "reachable": False, "error": exc.__class__.__name__}


def _resolves(name: str) -> bool:
    try:
        socket.getaddrinfo(name, None)
        return True
    except socket.gaierror:
        return False
    except OSError:
        return True  # unknown – don't raise a false alarm


async def _check_host_live(host: str, client: httpx.AsyncClient) -> list[dict]:
    out: list[dict] = []
    tls = await asyncio.to_thread(_tls_probe, host)
    if not tls["ok"]:
        if tls.get("reachable"):
            out.append(_f(host, "tls", "high", "TLS-Zertifikat ungültig", tls["error"]))
        else:
            out.append(_f(host, "tls", "info", "Kein HTTPS-Dienst erreichbar",
                          f"Port 443 antwortet nicht ({tls['error']}). Falls der Host keinen Webdienst hat, ist das ok."))
        return out
    try:
        expiry = datetime.strptime(tls["not_after"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expiry - datetime.now(timezone.utc)).days
        if days < 7:
            out.append(_f(host, "tls", "high", f"Zertifikat läuft in {days} Tagen ab"))
        elif days < 21:
            out.append(_f(host, "tls", "medium", f"Zertifikat läuft in {days} Tagen ab"))
        else:
            out.append(_f(host, "tls", "ok", f"Zertifikat gültig ({days} Tage, {tls['version']})",
                          f"Aussteller: {tls['issuer'].get('organizationName', '?')}"))
    except (TypeError, ValueError):
        pass
    if tls["version"] in ("TLSv1", "TLSv1.1"):
        out.append(_f(host, "tls", "high", f"Veraltetes Protokoll ausgehandelt: {tls['version']}"))

    try:
        r = await client.get(f"http://{host}/")
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 307, 308) and loc.lower().startswith("https://"):
            out.append(_f(host, "redirect", "ok", "HTTP leitet auf HTTPS um"))
        else:
            out.append(_f(host, "redirect", "medium", "HTTP wird nicht auf HTTPS umgeleitet",
                          f"http:// liefert Status {r.status_code}."))
    except httpx.HTTPError:
        pass

    try:
        r = await client.get(f"https://{host}/")
    except httpx.HTTPError as exc:
        out.append(_f(host, "headers", "info", "HTTPS-Abruf fehlgeschlagen", exc.__class__.__name__))
        return out
    headers = {k.lower(): v for k, v in r.headers.items()}
    missing = 0
    for name, (sev, title, detail) in SECURITY_HEADERS.items():
        if name not in headers:
            out.append(_f(host, "headers", sev, title, detail))
            missing += 1
    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        out.append(_f(host, "headers", "low", "Clickjacking-Schutz fehlt",
                      "Weder X-Frame-Options noch CSP frame-ancestors gesetzt."))
        missing += 1
    hsts = headers.get("strict-transport-security", "")
    if hsts and "max-age=" in hsts:
        try:
            age = int(hsts.split("max-age=")[1].split(";")[0].strip())
            if age < 15552000:
                out.append(_f(host, "headers", "low", "HSTS max-age zu kurz", f"{age}s, empfohlen ≥ 6 Monate."))
        except ValueError:
            pass
    for leak in ("x-powered-by", "x-aspnet-version"):
        if leak in headers:
            out.append(_f(host, "headers", "low", f"Header {leak} verrät Software", headers[leak][:80]))
    server = headers.get("server", "")
    if any(ch.isdigit() for ch in server) and server.lower() != "cloudflare":
        out.append(_f(host, "headers", "low", "Server-Header verrät Version", server[:80]))
    if not missing:
        out.append(_f(host, "headers", "ok", "Wichtige Security-Header vorhanden"))
    if r.status_code in (401, 403):
        out.append(_f(host, "auth", "ok", f"Zugriff geschützt (HTTP {r.status_code})"))
    elif r.status_code == 200 and any(k in r.text[:4000].lower() for k in ("index of /", "phpinfo()", "it works!")):
        out.append(_f(host, "content", "medium", "Standard-/Verzeichnis-Seite öffentlich",
                      "Die Startseite sieht nach Default-Seite oder Directory-Listing aus."))
    return out


def _txt(records: list[dict], name: str) -> list[str]:
    return [r["content"].strip('"') for r in records if r["type"] == "TXT" and r["name"] == name]


def _zone_checks(zone: dict, records: list[dict], zs: dict | None, dnssec: str | None) -> list[dict]:
    z = zone["name"]
    out: list[dict] = []
    if zs is None:
        out.append(_f(z, "zone", "info", "Zoneneinstellungen nicht lesbar",
                      "Dem API-Token fehlt 'Zone Settings: Read' – SSL-Modus etc. wurden nicht geprüft."))
    else:
        ssl_mode = zs.get("ssl")
        if ssl_mode in ("off", "flexible"):
            out.append(_f(z, "zone", "high", f"SSL-Modus '{ssl_mode}'",
                          "Cloudflare → Origin läuft unverschlüsselt. Auf 'Full (strict)' umstellen."))
        elif ssl_mode == "full":
            out.append(_f(z, "zone", "medium", "SSL-Modus 'Full' (ohne Zertifikatsprüfung)",
                          "Auf 'Full (strict)' umstellen, Origin-Zertifikat von Cloudflare nutzen."))
        elif ssl_mode == "strict":
            out.append(_f(z, "zone", "ok", "SSL-Modus 'Full (strict)'"))
        if zs.get("always_use_https") != "on":
            out.append(_f(z, "zone", "medium", "'Always Use HTTPS' ist aus"))
        min_tls = str(zs.get("min_tls_version") or "")
        if min_tls in ("1.0", "1.1"):
            out.append(_f(z, "zone", "medium", f"Minimale TLS-Version {min_tls}", "Mindestens 1.2 setzen."))
        if zs.get("tls_1_3") == "off":
            out.append(_f(z, "zone", "low", "TLS 1.3 deaktiviert"))
        hsts = (zs.get("security_header") or {}).get("strict_transport_security") or {}
        if not hsts.get("enabled"):
            out.append(_f(z, "zone", "low", "HSTS in Cloudflare nicht aktiviert",
                          "Alternativ am Origin setzen. Vorher sicherstellen, dass alle Subdomains HTTPS können."))
    if dnssec == "active":
        out.append(_f(z, "zone", "ok", "DNSSEC aktiv"))
    elif dnssec is not None:
        out.append(_f(z, "zone", "low", f"DNSSEC nicht aktiv ({dnssec})", "Schützt vor DNS-Spoofing; in Cloudflare 1-Klick."))

    has_mx = any(r["type"] == "MX" and r["name"] == z for r in records)
    spf = [t for t in _txt(records, z) if t.lower().startswith("v=spf1")]
    if not spf:
        sev = "medium" if has_mx else "low"
        hint = "SPF-Record anlegen." if has_mx else "Ohne Mailversand: 'v=spf1 -all' verhindert Spoofing mit dieser Domain."
        out.append(_f(z, "email", sev, "Kein SPF-Record", hint))
    elif len(spf) > 1:
        out.append(_f(z, "email", "medium", "Mehrere SPF-Records", "Nur ein v=spf1-Record ist erlaubt."))
    elif spf[0].rstrip().endswith(("+all", "?all")) or spf[0].strip().endswith(" all"):
        out.append(_f(z, "email", "high", "SPF erlaubt jeden Absender", spf[0][:120]))
    else:
        out.append(_f(z, "email", "ok", "SPF vorhanden", spf[0][:120]))
    dmarc = [t for t in _txt(records, f"_dmarc.{z}") if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        out.append(_f(z, "email", "medium", "Kein DMARC-Record", "Z.B. '_dmarc TXT v=DMARC1; p=reject;' für Domains ohne Mailversand."))
    elif "p=none" in dmarc[0].replace(" ", "").lower():
        out.append(_f(z, "email", "low", "DMARC nur im Monitoring (p=none)", dmarc[0][:120]))
    else:
        out.append(_f(z, "email", "ok", "DMARC aktiv", dmarc[0][:120]))
    if not any(r["type"] == "CAA" for r in records):
        out.append(_f(z, "dns", "low", "Kein CAA-Record", "Legt fest, welche CAs Zertifikate ausstellen dürfen."))
    for f in out:
        f["zone"] = True  # zone-wide finding, not tied to the apex host itself
    return out


def _record_checks(host: str, recs: list[dict], ddns_hosts: set[str]) -> list[dict]:
    out: list[dict] = []
    for r in recs:
        if r["type"] in ("A", "AAAA"):
            if _is_private(r["content"]):
                out.append(_f(host, "dns", "low", f"Private IP im öffentlichen DNS ({r['content']})",
                              "Verrät interne Netzstruktur. Interne Namen besser nur im lokalen DNS führen."))
            elif not r["proxied"]:
                sev = "medium" if host in ddns_hosts else "low"
                out.append(_f(host, "dns", sev, "Origin-IP öffentlich sichtbar (nicht proxied)",
                              f"{r['type']} {r['content']} – "
                              + ("Das ist deine Heim-IP aus dem DDNS. " if host in ddns_hosts else "")
                              + "Proxy (orange Wolke) aktivieren, falls es ein HTTP-Dienst ist."))
            else:
                out.append(_f(host, "dns", "ok", "Über Cloudflare-Proxy geschützt"))
        if host.startswith("*."):
            out.append(_f(host, "dns", "info", "Wildcard-Record",
                          "Jede beliebige Subdomain zeigt auf dieses Ziel – nur bewusst einsetzen."))
    return out


async def _dangling_cname(host: str, target: str) -> dict | None:
    if not await asyncio.to_thread(_resolves, target):
        return _f(host, "dns", "high", "CNAME-Ziel existiert nicht",
                  f"{target} löst nicht auf → möglicher Subdomain-Takeover. Record löschen oder Ziel reparieren.")
    return None


def score(findings: list[dict]) -> int:
    return max(0, 100 - sum(_WEIGHT.get(f["severity"], 0) for f in findings))


# Manual and scheduled scans share the network and the GPU, so they run one after another.
_scan_lock = asyncio.Lock()


async def run_scan(hosts: list[str], progress) -> dict:
    """hosts: hostnames that exist as records in the account (validated by caller)."""
    async with _scan_lock:
        return await _run_scan(hosts, progress)


async def _run_scan(hosts: list[str], progress) -> dict:
    started = time.time()
    all_records = await cf.all_records()
    zones = {z["id"]: z for z in await cf.zones()}
    ddns_hosts = managed_names()
    by_host: dict[str, list[dict]] = {}
    for r in all_records:
        by_host.setdefault(r["name"], []).append(r)

    findings: list[dict] = []
    zone_ids = sorted({by_host[h][0]["zone_id"] for h in hosts if h in by_host})
    total = len(zone_ids) + len(hosts)
    done = 0
    for zid in zone_ids:
        zrecs = [r for r in all_records if r["zone_id"] == zid]
        zs, sec = await asyncio.gather(cf.zone_settings(zid), cf.dnssec(zid))
        findings += _zone_checks(zones[zid], zrecs, zs, sec)
        done += 1
        progress(done, total)

    sem = asyncio.Semaphore(5)
    async with httpx.AsyncClient(follow_redirects=False, timeout=8.0, verify=True,
                                 headers={"User-Agent": "DomainManager-SecurityCheck/1.0"}) as client:
        async def one(host: str) -> list[dict]:
            nonlocal done
            async with sem:
                recs = by_host.get(host, [])
                out = _record_checks(host, recs, ddns_hosts)
                for r in recs:
                    if r["type"] == "CNAME":
                        hit = await _dangling_cname(host, r["content"])
                        if hit:
                            out.append(hit)
                if not host.startswith("*.") and any(r["type"] in ("A", "AAAA", "CNAME") for r in recs):
                    out += await _check_host_live(host, client)
                done += 1
                progress(done, total)
                return out
        for chunk in await asyncio.gather(*(one(h) for h in hosts)):
            findings += chunk

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["host"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    return {"hosts": hosts, "findings": findings, "counts": counts, "score": score(findings),
            "duration": round(time.time() - started, 1)}
