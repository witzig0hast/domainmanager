# DomainManager

Selbst gehostetes Dashboard im Cloudflare-Look für dein Homelab – **ein einziger Container**:

- **Eingebauter DDNS-Updater** (ersetzt `favonia/cloudflare-ddns`): hält die A/AAAA-Records deiner Hosts auf deiner öffentlichen IP – pro Host einstellbar: IPv4/IPv6, **Proxy an/aus**, TTL, pausieren
- **Import** deiner bisherigen favonia-Subdomains (aus dem Compose-Ordner, per Einfügen oder als Vorschlag aus Cloudflare)
- **DNS-Einträge** aller Zonen ansehen, Proxy per Klick auf die Wolke umschalten, optional löschen
- **Sicherheitscheck** deiner Domains mit Zusammenfassung durch dein **lokales Ollama-Modell**
- **Wochen-Scan**: prüft automatisch in kleinen Blöcken, bis alle Subdomains im eingestellten Zeitraum (z. B. 7 Tage) getestet sind – optional nur nachts
- **Nginx Proxy Manager anbinden**: meldet ungenutzte Subdomains (kein Proxy-Host, Host deaktiviert, Backend offline, nur 404-Host) und NPM-Hosts ohne DNS-Eintrag
- **IP-Verlauf**, optionale **Push-Benachrichtigung** bei IP-Wechsel (ntfy, Discord), **Audit-Log**

```
 Browser ──HTTPS──▶ dashboard (uid 10001, read-only, kein Docker-Socket)
                      ├─▶ 1.1.1.1/cdn-cgi/trace   öffentliche IP ermitteln (Fallback: ipify)
                      ├─▶ api.cloudflare.com      Records anlegen/korrigieren (API-Token)
                      ├─▶ Ollama im LAN           Sicherheits-Zusammenfassung
                      ├─▶ Nginx Proxy Manager     Proxy-Hosts lesen (nur lesend), Backends per TCP prüfen
                      └─▶ deine Hosts             TLS-/HTTP-Checks
```

## Sicherheitskonzept

| Ebene | Maßnahme |
|---|---|
| Netzwerk | Lauscht standardmäßig nur auf `127.0.0.1`; IP-Allowlist (`ALLOWED_NETWORKS`, Default nur private Netze); HTTPS ab Werk (selbstsigniertes Zertifikat) |
| Login | Argon2id-Passwort-Hash, optional TOTP-2FA (mit Replay-Schutz), Lockout nach 5 Fehlversuchen/IP + globales Limit |
| Login | Optional **SSO über Authentik** (OpenID Connect, Code-Flow mit PKCE, Prüfung von Issuer/Audience/Nonce, Zugriff nur für bestimmte Gruppen); Passwort-Login abschaltbar |
| Sitzung | Zufälliges Session-Token, Cookie `HttpOnly; Secure; SameSite=Strict`; serverseitig nur als SHA-256-Hash gespeichert, übersteht Neustarts; 12 h Inaktivität / 7 Tage max. (einstellbar); mehrere Geräte, „Alle anderen abmelden“ |
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

touch secrets/admin_password_hash secrets/totp_secret secrets/npm_password secrets/oidc_client_secret
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

## SSO mit Authentik

1. Authentik → *Applications → Create with Provider* → **OAuth2/OpenID Provider**:
   - Client type: **Confidential**
   - Redirect URI (strict): `https://<dashboard-adresse>:8443/api/oidc/callback` – genau die Adresse, mit der du das Dashboard im Browser öffnest
   - Scopes: `openid`, `email`, `profile` (Standard; `profile` liefert die Gruppen)
   - Signing Key: beliebig
2. In Authentik eine Gruppe `domainmanager-admins` anlegen, dich hinzufügen und die Application optional per *Policy/Group Binding* auf diese Gruppe beschränken.
3. In `.env`: `OIDC_ISSUER_URL` (aus dem Provider, „OpenID Configuration Issuer“, z. B. `https://auth.example.org/application/o/domainmanager/`), `OIDC_CLIENT_ID`, `OIDC_ALLOWED_GROUPS=domainmanager-admins`. Das Client-Secret in `secrets/oidc_client_secret` (`chown 10001:10001`, `chmod 400`).
4. `docker compose up -d` → auf der Login-Seite erscheint **„Mit Authentik anmelden“**.
5. Klappt das, `LOCAL_LOGIN=false` setzen – dann gibt es nur noch SSO.

Fehler beim SSO-Login werden auf der Login-Seite angezeigt und im Audit-Log protokolliert. Häufigste Ursache: Redirect-URI in Authentik stimmt nicht exakt (Port, `https`). Dann `OIDC_REDIRECT_URI` setzen und in Authentik identisch eintragen.

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

## Nginx Proxy Manager anbinden

1. In NPM unter *Users* einen eigenen Benutzer anlegen (z. B. `domainmanager@lan`), **ohne** Admin-Rolle, Berechtigungen: *Proxy Hosts*, *Redirection Hosts*, *404 Hosts* jeweils **View Only**, alles andere *Hidden*. Kein 2FA für diesen Benutzer.
2. In `.env`: `NPM_URL=http://<npm-ip>:81` und `NPM_EMAIL=domainmanager@lan`; das Passwort in `secrets/npm_password` (danach `chown 10001:10001 secrets/npm_password && chmod 400 secrets/npm_password`).
3. `docker compose up -d` → Seite **NPM-Abgleich**.

Für jede Subdomain (A/AAAA/CNAME) gibt es einen Status:

| Status | Bedeutung |
|---|---|
| **Ungenutzt** | zeigt auf deine Heim-IP (bzw. ist ein DDNS-Host oder CNAME darauf), aber kein NPM-Host ist dafür zuständig |
| **Backend offline** | NPM-Proxy-Host existiert, aber das Ziel (`forward_host:port`) antwortet nicht per TCP |
| **Deaktiviert** | nur deaktivierte NPM-Hosts |
| **404-Host** | in NPM nur als 404-Host eingetragen |
| **Genutzt** | aktiver Proxy- oder Redirect-Host (auch über NPM-Wildcards wie `*.apps.example.org`) |
| **Extern** | zeigt nicht auf dein Netz (z. B. Mailanbieter, Vercel) – wird nicht bewertet |

Zusätzlich: **NPM-Hosts ohne DNS-Eintrag** (Altlasten in NPM). Der Abgleich läuft automatisch alle 6 Stunden; neu ungenutzte Subdomains werden einmalig per `NOTIFY_URL` gemeldet. Mit *Ignorieren* blendest du bewusst ungenutzte Einträge aus. Bei aktivem `ALLOW_DNS_DELETE` kannst du den Record direkt löschen.

## Wochen-Scan

Seite **Wochen-Scan**: Zeitraum (z. B. *7 Tage*), Abstand der Blöcke (z. B. *alle 6 h*) und optional ein Zeitfenster (z. B. *01:00–06:00*, Zeitzone `TZ`). Pro Block werden nur so viele Hosts geprüft, dass am Ende des Zeitraums alle getestet sind; die am längsten nicht geprüften kommen zuerst. Fällt etwas aus (Server aus, Zeitfenster zu klein), holt der Scan zum Ende des Zeitraums automatisch auf. Ist ein Durchgang komplett, gibt es eine KI-Zusammenfassung (Modell nur kurz geladen) und eine Benachrichtigung; der nächste Durchgang startet nach Ablauf des Zeitraums. Neue hohe/kritische Befunde werden sofort gemeldet. Einzelne Hosts lassen sich ausschließen; manuelle Scans zählen mit.

## Bedienung

- **Proxy umschalten:** Klick auf die Wolke – in der DDNS-Liste oder bei jedem Record unter *DNS-Einträge*. Bei DDNS-Hosts wird die Einstellung gespeichert, sonst würde der nächste Lauf sie zurückdrehen.
- **Host entfernen:** Mülleimer in der DDNS-Liste. Der Record bleibt bei Cloudflare stehen, außer du hakst „auch löschen“ an (`ALLOW_DNS_DELETE=true`).
- **Neuer Host:** Name eintragen → *Hinzufügen*. Gibt es noch keinen Record, wird er beim nächsten Lauf angelegt (Kommentar „DomainManager DDNS“).
- **Benachrichtigung:** `NOTIFY_URL=https://ntfy.sh/<geheimes-topic>` (oder ein ntfy-kompatibler Endpunkt) bzw. eine Discord-Webhook-URL.
- **Sicherheitscheck:** Hosts wählen (Schnellwahl „Alle DDNS-Hosts“ / „Alle ohne Proxy“), Modell wählen, *Scan starten*. Geprüft werden u. a. SSL-Modus, Always-HTTPS, TLS-Version, HSTS, DNSSEC, SPF/DMARC/CAA, sichtbare Heim-IP, private IPs im DNS, verwaiste CNAMEs (Subdomain-Takeover), Zertifikat, HTTPS-Redirect, Security-Header und Versions-Leaks.

## Fehlersuche

**DDNS-Updater „läuft, macht aber nichts“** – DDNS-Seite öffnen:

- Der Status oben sagt jetzt genau, was los ist: *Aktiv*, *Pausiert*, *Keine Hosts*, *Fehler* oder *Hängt*.
- **Protokoll**: jeder Lauf mit ermittelter IP, Änderungen und Fehlern. Dieselben Zeilen stehen in `docker compose logs dashboard` (`DDNS [auto]: IPv4=…; 0 geändert, 3 aktuell, 0 Fehler`). „aktuell“ heißt: der Record stimmt bereits, es gibt nichts zu tun.
- **Diagnose**: fragt jeden IP-Dienst einzeln ab, prüft den Cloudflare-Token und macht einen Schreibtest an einem bestehenden Record (ohne ihn zu ändern).
  - Alle IPv4-Dienste schlagen fehl → der Container kommt nicht ins Internet (Firewall, DNS, Docker-Netz).
  - Schreibtest „Authentication error“ → dem Token fehlt **Zone → DNS → Edit** (in älteren Anleitungen stand *Read*).
  - Zonen-Liste leer → Token gilt nicht für deine Zone (*Zone Resources*).

**Ständig abgemeldet**: Sitzungen überstehen jetzt Neustarts, gelten 12 h ohne Aktivität (`SESSION_IDLE_MINUTES`) und hängen nicht mehr an der IP (Wechsel IPv4↔IPv6 hatte vorher abgemeldet). Mehrere Geräte gleichzeitig sind erlaubt; unter *Audit-Log → Aktive Sitzungen* siehst du alle und kannst die anderen abmelden. Läuft das Dashboard hinter einem Reverse-Proxy, `TRUSTED_PROXIES` setzen.

## Wartung

- Updates: `git pull && docker compose build --pull && docker compose up -d`
- Daten (DDNS-Hosts, Verlauf, Audit-Log, Zertifikat) liegen im Volume `dm-data` (`/data`). Sichern z. B. mit
  `docker run --rm -v domainmanager_dm-data:/d -v "$PWD":/b alpine tar czf /b/dm-data.tgz -C /d .`
- Passwort ändern: Hash-Schritt aus 2. wiederholen, `docker compose up -d --force-recreate`
