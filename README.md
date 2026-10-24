# DomainManager

Selbst gehostetes Dashboard im Cloudflare-Look für dein Homelab – **ein einziger Container**:

- **Eingebauter DDNS-Updater** (ersetzt `favonia/cloudflare-ddns`): hält die A/AAAA-Records deiner Hosts auf deiner öffentlichen IP – pro Host einstellbar: IPv4/IPv6, **Proxy an/aus**, TTL, pausieren
- **Import** deiner bisherigen favonia-Subdomains (aus dem Compose-Ordner, per Einfügen oder als Vorschlag aus Cloudflare)
- **DNS-Einträge** aller Zonen ansehen, Proxy per Klick auf die Wolke umschalten, optional löschen
- **Sicherheitscheck** deiner Domains mit Zusammenfassung durch dein **lokales Ollama-Modell**
- **IP-Verlauf**, optionale **Push-Benachrichtigung** bei IP-Wechsel (ntfy, Discord), **Audit-Log**

```
 Browser ──HTTPS──▶ dashboard (uid 10001, read-only, kein Docker-Socket)
                      ├─▶ 1.1.1.1/cdn-cgi/trace   öffentliche IP ermitteln (Fallback: ipify)
                      ├─▶ api.cloudflare.com      Records anlegen/korrigieren (API-Token)
                      ├─▶ Ollama im LAN           Sicherheits-Zusammenfassung
                      └─▶ deine Hosts             TLS-/HTTP-Checks
```

## Sicherheitskonzept

| Ebene | Maßnahme |
|---|---|
| Netzwerk | Lauscht standardmäßig nur auf `127.0.0.1`; IP-Allowlist (`ALLOWED_NETWORKS`, Default nur private Netze); HTTPS ab Werk (selbstsigniertes Zertifikat) |
| Login | Argon2id-Passwort-Hash, optional TOTP-2FA (mit Replay-Schutz), Lockout nach 5 Fehlversuchen/IP + globales Limit |
| Sitzung | Zufälliges Server-Session-Token, Cookie `HttpOnly; Secure; SameSite=Strict`, an Client-IP gebunden, 30 min Idle / 8 h max., nur eine aktive Sitzung |
| Requests | CSRF-Token für alle schreibenden Requests + Origin-Prüfung, Body-Limit 64 KB, keine OpenAPI/Docs-Endpunkte |
| Browser | Strikte CSP (`default-src 'none'`, kein Inline-JS), `X-Frame-Options: DENY`, `no-referrer`, kein `innerHTML` mit Daten |
| Container | Read-only Root-FS, `cap_drop: ALL`, `no-new-privileges`, Non-Root, Memory/PID-Limits, **kein Docker-Socket**, Secrets als Docker Secrets |
| Cloudflare | Eingeschränkter API-Token; DNS-Löschen standardmäßig **aus** und mit Namens-Bestätigung |
| DDNS | Nur gültige, **öffentliche** IPs werden geschrieben (mehrere Anbieter, private/ungültige Antworten verworfen); ist die IP unbekannt, wird nichts geändert; nur Hosts in deinen eigenen Zonen |
| Import | Liest nur `DOMAINS`, `IP4_DOMAINS`, `IP6_DOMAINS`, `PROXIED` – Tokens werden nie gespeichert oder angezeigt; Ordner nur read-only eingebunden |
| Nachvollziehbarkeit | Audit-Log in `/data/audit.log` (Logins, jede Änderung, jede DDNS-Aktualisierung, IP-Wechsel) |

## Welches Ollama-Modell?

Die Prüfungen sind **deterministischer Code** – das Modell fasst nur die Befunde auf Deutsch zusammen und priorisiert sie. Dafür reicht ein kleines Modell:

| Modell | VRAM (8k Kontext) | Eignung |
|---|---|---|
| **`qwen2.5:7b-instruct`** (Standard) | ~5–6 GB | ✅ Beste Wahl: zuverlässiges JSON, gutes Deutsch, schnell auf der P40 |
| `llama3.1:8b` / `hermes3:8b` | ~6 GB | ✅ Gute Alternativen |
| `gemma2:9b` | ~7 GB | ok, etwas langsamer |
| `llama3.2:1b` | ~1,5 GB | ⚠️ Zu schwach – erfindet Dinge, JSON oft kaputt |
| `qwen3.8:27b`, `qwen2.5-coder:32b`, `nemotron-3-nano`, `llava:34b` | 17–24 GB | ❌ Im Dashboard ausgeblendet (`OLLAMA_MAX_MODEL_GB=10`) |

Das Modell wird nur für den Scan geladen und nach `OLLAMA_KEEP_ALIVE=2m` wieder entladen (`0` = sofort). Ollama muss im LAN erreichbar sein (`OLLAMA_HOST=0.0.0.0`) – per Firewall nur den Docker-Host zulassen, die Ollama-API hat keinen Login.

## Installation

### 1. Cloudflare API-Token anlegen

Cloudflare → *My Profile → API Tokens → Create Token → Custom token*:

| Berechtigung | Wofür |
|---|---|
| Zone → **Zone** → Read | Zonen auflisten |
| Zone → **DNS** → **Edit** | DDNS-Updates, Proxy umschalten (und Löschen, falls `ALLOW_DNS_DELETE=true`) |
| Zone → **Zone Settings** → Read | SSL-Modus, HSTS, TLS-Version im Sicherheitscheck |

*Zone Resources*: nur deine Zonen. *Client IP Address Filtering* bitte **nicht** setzen – deine IP ändert sich ja, genau dafür ist DDNS da.

### 2. Konfigurieren

```bash
git clone https://github.com/witzig0hast/domainmanager.git && cd domainmanager
cp .env.example .env && nano .env        # OLLAMA_URL, BIND_ADDR, TLS_HOSTNAMES, DDNS_IMPORT_DIR …

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

### 3. Starten

```bash
docker compose up -d && docker compose logs -f
```

Aufruf: `https://<BIND_ADDR>:8443` – das selbstsignierte Zertifikat einmalig akzeptieren. Trag die LAN-IP/den Namen in `TLS_HOSTNAMES` ein, **bevor** du das erste Mal startest.

**Hinter einem Reverse-Proxy** (Traefik/NPM/Caddy): `TLS_MODE=off`, `TRUSTED_PROXIES=<Proxy-IP>`, `BIND_ADDR` auf eine Adresse, die nur der Proxy erreicht. **Nie** ohne zusätzlichen Schutz (Cloudflare Access/VPN) ins Internet stellen.

## Umstieg von favonia/cloudflare-ddns

Der Updater startet **pausiert**, damit nichts doppelt läuft:

1. In `.env` `DDNS_IMPORT_DIR` auf deinen alten Ordner setzen, z. B.
   `DDNS_IMPORT_DIR=/srv/dev-disk-by-uuid-48b0f4f1-fec6-47f4-9fe8-1407e62e6bba/serverdir/services/Compose/CloudflareDNS`
   und `docker compose up -d`. Der Ordner wird nur lesend eingebunden.
2. Dashboard → **DDNS → Importieren → „Aus favonia-Ordner“**. Erkannt werden `DOMAINS` (IPv4+IPv6), `IP4_DOMAINS`, `IP6_DOMAINS` – auch über `${VARIABLEN}` aus der `.env` – und `PROXIED=true/false`. Bei bestehenden Records wird deren aktueller Proxy-Status übernommen. Alternativ: Tab **„Vorschläge aus Cloudflare“** (alle Records, die gerade auf deine IP zeigen) oder **„Einfügen“**.
3. Proxy/IPv4/IPv6 je Host prüfen, importieren.
4. favonia stoppen: im CloudflareDNS-Ordner `docker compose down`.
5. Im Dashboard den Updater **einschalten** und **„Jetzt aktualisieren“** – in der Status-Spalte sollte überall „aktuell“ stehen.
6. `DDNS_IMPORT_DIR` wieder auskommentieren, `docker compose up -d`. Den favonia-Ordner kannst du danach löschen.

> Laufen favonia und der Updater gleichzeitig, kämpfen sie um den Proxy-Status, weil favonia bei jedem Lauf seinen `PROXIED`-Wert zurücksetzt.

### IPv6 (AAAA-Records)

favonia lief mit `network_mode: host` und hatte daher IPv6. Der DomainManager läuft absichtlich in einem eigenen Netz. Brauchst du AAAA-Records: `DDNS_IPV6=true` in `.env` – das aktiviert IPv6 im Compose-Netz (Docker ≥ 27, der Host braucht eine öffentliche IPv6). Danach in der DDNS-Ansicht prüfen, ob unter „Öffentliche IP“ eine IPv6 erscheint. Ohne IPv6 werden AAAA-Records nicht angefasst; der Status weist auf vorhandene, nicht gepflegte AAAA-Records hin.

## Bedienung

- **Proxy umschalten:** Klick auf die Wolke – in der DDNS-Liste oder bei jedem Record unter *DNS-Einträge*. Bei DDNS-Hosts wird die Einstellung gespeichert, sonst würde der nächste Lauf sie zurückdrehen.
- **Host entfernen:** Mülleimer in der DDNS-Liste. Der Record bleibt bei Cloudflare stehen, außer du hakst „auch löschen“ an (`ALLOW_DNS_DELETE=true`).
- **Neuer Host:** Name eintragen → *Hinzufügen*. Gibt es noch keinen Record, wird er beim nächsten Lauf angelegt (Kommentar „DomainManager DDNS“).
- **Benachrichtigung:** `NOTIFY_URL=https://ntfy.sh/<geheimes-topic>` (oder ein ntfy-kompatibler Endpunkt) bzw. eine Discord-Webhook-URL.
- **Sicherheitscheck:** Hosts wählen (Schnellwahl „Alle DDNS-Hosts“ / „Alle ohne Proxy“), Modell wählen, *Scan starten*. Geprüft werden u. a. SSL-Modus, Always-HTTPS, TLS-Version, HSTS, DNSSEC, SPF/DMARC/CAA, sichtbare Heim-IP, private IPs im DNS, verwaiste CNAMEs (Subdomain-Takeover), Zertifikat, HTTPS-Redirect, Security-Header und Versions-Leaks.

## Wartung

- Updates: `git pull && docker compose build --pull && docker compose up -d`
- Daten (DDNS-Hosts, Verlauf, Audit-Log, Zertifikat) liegen im Volume `dm-data` (`/data`). Sichern z. B. mit
  `docker run --rm -v domainmanager_dm-data:/d -v "$PWD":/b alpine tar czf /b/dm-data.tgz -C /d .`
- Passwort ändern: Hash-Schritt aus 2. wiederholen, `docker compose up -d --force-recreate`
