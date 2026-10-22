# DomainManager

Selbst gehostetes Dashboard im Cloudflare-Look für dein Homelab:

- **DNS-Einträge** aller Cloudflare-Zonen ansehen (Proxy-Status mit oranger/grauer Wolke, Filter, Suche) und optional löschen
- **DDNS-Domains** von [`favonia/cloudflare-ddns`](https://github.com/favonia/cloudflare-ddns) entfernen/hinzufügen – inkl. automatischem Neu-Erstellen des Containers
- **Sicherheitscheck** deiner Domains/Subdomains: deterministische Prüfungen + Zusammenfassung und priorisierte Maßnahmen durch dein **lokales Ollama-Modell**
- **Audit-Log** aller Anmeldungen und Änderungen

```
                ┌──────────────── LAN ────────────────┐
 Browser ──HTTPS──▶ dashboard (uid 10001, read-only)  │──▶ api.cloudflare.com (API-Token)
                │     │  schreibt managed/ddns.env     │──▶ Ollama im LAN (qwen2.5:7b-instruct)
                │     │  legt request.json ab          │──▶ deine Hosts (TLS/HTTP-Checks)
                │     ▼                                │
                │  applier (KEIN Netzwerk)             │
                │     └─ docker compose up -d cloudflare-ddns  (einziger Befehl)
                └──────────────────────────────────────┘
```

## Sicherheitskonzept

| Ebene | Maßnahme |
|---|---|
| Netzwerk | Lauscht standardmäßig nur auf `127.0.0.1`; IP-Allowlist (`ALLOWED_NETWORKS`, Default nur private Netze); HTTPS ab Werk (selbstsigniertes Zertifikat) |
| Login | Argon2id-Passwort-Hash, optional TOTP-2FA (mit Replay-Schutz), Lockout nach 5 Fehlversuchen/IP + globales Limit, gleiche Antwortzeit bei falschem Benutzernamen |
| Sitzung | Zufälliges Server-Session-Token, Cookie `HttpOnly; Secure; SameSite=Strict`, an Client-IP gebunden, 30 min Idle / 8 h max., nur eine aktive Sitzung |
| Requests | CSRF-Token für alle schreibenden Requests + Origin-Prüfung, Body-Limit 64 KB, keine OpenAPI/Docs-Endpunkte |
| Browser | Strikte CSP (`default-src 'none'`, kein Inline-JS), `X-Frame-Options: DENY`, `no-referrer`, COOP/CORP, kein `innerHTML` mit Daten |
| Container | Read-only Root-FS, `cap_drop: ALL`, `no-new-privileges`, Non-Root (uid 10001), Memory/PID-Limits, keine Secrets in Env-Variablen (Docker Secrets) |
| Docker-Socket | Nur der **Applier** hat ihn – ohne Netzwerk (`network_mode: none`), ohne Eingaben: eine Anfrage-Datei löst genau einen fest verdrahteten Befehl aus (max. alle 10 s). Komplett abschaltbar. |
| Cloudflare | Eingeschränkter API-Token statt Global Key; DNS-Löschen ist standardmäßig **aus** und verlangt das Eintippen des Namens |
| Scanner | Prüft nur Hostnamen, die als Record in deinen Zonen existieren (kein frei wählbares Ziel), max. 25 Hosts/Scan |
| DDNS-Datei | Nur die Domain-Schlüssel werden gelesen/geschrieben, andere Zeilen bleiben unangetastet und werden nie ans Frontend geschickt; Backup vor jeder Änderung (letzte 10) |
| Nachvollziehbarkeit | Audit-Log in `/data/audit.log` und im Container-Log |

## Welches Ollama-Modell?

Die eigentlichen Prüfungen sind **deterministischer Code** – das Modell muss nur die Befunde auf Deutsch zusammenfassen und als JSON priorisieren. Dafür reicht ein kleines Modell:

| Modell | VRAM (8k Kontext) | Eignung |
|---|---|---|
| **`qwen2.5:7b-instruct`** (Standard) | ~5–6 GB | ✅ Beste Wahl: zuverlässiges JSON, gutes Deutsch, schnell auf der P40 |
| `llama3.1:8b` / `hermes3:8b` | ~6 GB | ✅ Gute Alternativen |
| `gemma2:9b` | ~7 GB | ok, etwas langsamer |
| `llama3.2:1b` | ~1,5 GB | ⚠️ Zu schwach – erfindet Dinge, JSON oft kaputt |
| `qwen3.8:27b`, `qwen2.5-coder:32b`, `nemotron-3-nano`, `llava:34b` | 17–24 GB | ❌ Belegt fast die ganze P40 – im Dashboard ausgeblendet (`OLLAMA_MAX_MODEL_GB=10`) |

Damit die P40 nicht dauerhaft belegt ist, wird das Modell nur für den Scan geladen und nach `OLLAMA_KEEP_ALIVE=2m` wieder entladen (`0` = sofort). Optional auf dem Ollama-Host `OLLAMA_MAX_LOADED_MODELS=1` setzen.

Ollama muss im LAN erreichbar sein (`OLLAMA_HOST=0.0.0.0`). Die Ollama-API hat keine Authentifizierung – per Firewall nur den Docker-Host zulassen, z. B. `ufw allow from <docker-host-ip> to any port 11434`.

## Installation

### 1. Cloudflare API-Token anlegen

Cloudflare → *My Profile → API Tokens → Create Token → Custom token*:

| Berechtigung | Wofür |
|---|---|
| Zone → **Zone** → Read | Zonen auflisten |
| Zone → **DNS** → Read | Records anzeigen (→ **Edit**, nur wenn du `ALLOW_DNS_DELETE=true` willst) |
| Zone → **Zone Settings** → Read | SSL-Modus, HSTS, TLS-Version im Sicherheitscheck |

*Zone Resources*: nur deine Zonen. *Client IP Address Filtering*: deine öffentliche IP. Den Global API Key bitte **nicht** verwenden. Nimm nicht denselben Token wie cloudflare-ddns.

### 2. cloudflare-ddns auf eine Domain-Datei umstellen

cloudflare-ddns liest `DOMAINS` nur aus Umgebungsvariablen. Damit das Dashboard die Liste ändern kann, ohne an deine `docker-compose.yml` zu müssen, kommt sie in eine eigene Datei:

```bash
cd /srv/dev-disk-by-uuid-48b0f4f1-fec6-47f4-9fe8-1407e62e6bba/serverdir/services/Compose/CloudflareDNS
cp docker-compose.yml docker-compose.yml.bak
mkdir managed
# Die DOMAINS-Zeile(n) aus docker-compose.yml/.env hierhin verschieben (ohne "- " und ohne Anführungszeichen):
echo 'DOMAINS=example.org,www.example.org,nas.example.org' > managed/ddns.env
chown -R 10001:10001 managed && chmod 755 managed && chmod 644 managed/ddns.env
```

Dann in `docker-compose.yml` beim Service `cloudflare-ddns` ergänzen und die alten `DOMAINS`/`IP4_DOMAINS`/`IP6_DOMAINS` dort entfernen (Beispiel: [`examples/CloudflareDNS-docker-compose.yml`](examples/CloudflareDNS-docker-compose.yml)):

```yaml
    env_file:
      - ./managed/ddns.env
```

```bash
docker compose up -d && docker compose logs --tail 20 cloudflare-ddns   # Domains sollten wie vorher erkannt werden
```

> Wichtig: In `managed/ddns.env` gehören **nur** Domain-Listen – der Cloudflare-Token bleibt, wo er ist.

### 3. DomainManager konfigurieren

```bash
git clone https://github.com/witzig0hast/domainmanager.git && cd domainmanager
cp .env.example .env && nano .env        # DDNS_PROJECT_DIR, OLLAMA_URL, BIND_ADDR, TLS_HOSTNAMES …

touch secrets/admin_password_hash secrets/totp_secret
printf '%s' 'DEIN_CLOUDFLARE_TOKEN' > secrets/cf_api_token

docker compose build
# Passwort-Hash erzeugen (Eingabe ist unsichtbar), wird direkt nach secrets/ geschrieben:
docker compose run --rm --no-deps -u 0 -v "$PWD/secrets:/out" --entrypoint python \
  dashboard -m app.cli hash-password /out/admin_password_hash
# Optional, aber empfohlen: 2FA. Das angezeigte Secret bzw. die otpauth://-URI in die Authenticator-App eintragen.
docker compose run --rm --no-deps -u 0 -v "$PWD/secrets:/out" --entrypoint python \
  dashboard -m app.cli totp-secret /out/totp_secret

# Die Secrets werden in den Container gemountet und müssen für uid 10001 lesbar sein:
chown 10001:10001 secrets/* && chmod 400 secrets/*
```

### 4. Starten

```bash
docker compose up -d
docker compose logs -f
```

Aufruf: `https://<BIND_ADDR>:8443` – das selbstsignierte Zertifikat einmalig im Browser akzeptieren (Fingerprint: `openssl x509 -noout -fingerprint -sha256 -in` auf `/data/tls/cert.pem` im Volume). Trag die LAN-IP/den Namen in `TLS_HOSTNAMES` ein, **bevor** du das erste Mal startest (sonst Volume-Datei `tls/` löschen und neu starten).

**Hinter einem Reverse-Proxy** (Traefik/NPM/Caddy mit gültigem Zertifikat): `TLS_MODE=off`, `TRUSTED_PROXIES=<Proxy-IP>`, `COOKIE_SECURE=true` lassen, `BIND_ADDR` auf eine Adresse, die nur der Proxy erreicht. **Nie** ohne zusätzlichen Schutz (z. B. Cloudflare Access/VPN) ins Internet stellen.

## Bedienung

**DDNS-Domain entfernen:** *DDNS-Domains* → bei der Subdomain *Entfernen* → *Änderungen speichern* → *Jetzt anwenden*. Der Applier führt im CloudflareDNS-Ordner `docker compose up -d --no-deps cloudflare-ddns` aus. Hinweis: cloudflare-ddns löscht den DNS-Record dabei **nicht** – er bleibt mit der letzten IP bestehen. Ist `ALLOW_DNS_DELETE=true` (Token mit *DNS: Edit*), kannst du ihn im selben Dialog mitlöschen.

**Sicherheitscheck:** Hosts auswählen (Schnellwahl „Alle DDNS-Hosts“ / „Alle ohne Proxy“), Modell wählen, *Scan starten*. Geprüft werden u. a.:

- Zone: SSL-Modus (Flexible/Full/Strict), Always-HTTPS, min. TLS-Version, TLS 1.3, HSTS, DNSSEC
- E-Mail-Spoofing: SPF (fehlend/`+all`/mehrfach), DMARC (fehlend/`p=none`), CAA
- DNS: Origin-/Heim-IP ohne Proxy sichtbar, private IPs im öffentlichen DNS, Wildcards, **CNAME auf nicht existierende Ziele (Subdomain-Takeover)**
- Live: Zertifikat gültig/Ablauf, Protokoll, HTTP→HTTPS-Redirect, Security-Header (HSTS, CSP, nosniff, Clickjacking, Referrer-Policy), Versions-Leaks (`Server`, `X-Powered-By`), Default-Seiten/Directory-Listing

Die Live-Prüfungen laufen aus deinem LAN – bei Split-DNS siehst du ggf. die interne statt der öffentlichen Sicht.

## Applier deaktivieren (kein Docker-Socket)

Der Docker-Socket entspricht Root-Rechten auf dem Host. Wer das gar nicht will: in `.env` `APPLIER_ENABLED=false` setzen und den Service `applier` in `docker-compose.yml` auskommentieren. Nach Änderungen dann manuell im CloudflareDNS-Ordner `docker compose up -d` ausführen.

## Wartung

- Updates: `git pull && docker compose build --pull && docker compose up -d`
- Backups der DDNS-Datei: `managed/ddns.env.bak-*` (die letzten 10)
- Audit-Log: Seite *Audit-Log* oder `docker compose exec dashboard tail /data/audit.log`
- Passwort ändern: Schritt 3 wiederholen, `docker compose up -d --force-recreate dashboard`
