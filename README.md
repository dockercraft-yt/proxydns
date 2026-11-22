# ProxyDNS Manager

![Version](https://img.shields.io/badge/version-0.0.1--alpha-orange)
![Status](https://img.shields.io/badge/status-ALPHA-red)

> [!WARNING]
> **ALPHA-Version 0.0.1-alpha** – frühe Testversion. Funktionen, Bedienung und das Datenformat können
> sich noch ändern, Fehler sind wahrscheinlich. Bitte nicht als einzige Verwaltung für wichtige
> Systeme einsetzen und vor Updates die Daten sichern (Docker-Volume bzw. `~/.config/proxydns/`).

Legt in **einem Schritt** einen lokalen DNS-Eintrag in **Pi-hole v6** und den passenden
Proxy-Host in **Nginx Proxy Manager (NPM)** an:

```
app.home.lan  ──Pi-hole──▶  IP von NPM  ──NPM──▶  http://192.168.1.20:8080
```

Läuft als **Docker-Container** (Weboberfläche im LAN) oder als **Desktop-App** mit eigenem
Fenster unter Windows und Linux (kein offener Netzwerk-Port).

---

## Funktionen

- Einträge anzeigen (Pi-hole + NPM zusammengeführt, mit Status) und neu anlegen
- Alle NPM-Optionen: bestehende Zertifikate, Force SSL, HTTP/2, HSTS (+Subdomains),
  WebSockets, Exploit-Schutz, Caching, Access Lists, Custom Locations,
  erweiterte Nginx-Konfiguration (nur Admins)
- Automatischer **Rollback**: schlägt NPM fehl, wird der DNS-Eintrag wieder entfernt
- Benutzer mit Rollen **admin** / **user**, optional **TOTP-2FA**, optional **OIDC** (nur Docker)
- **Audit-Log**, kryptografisch verkettet – Manipulationen an der Datenbank werden erkannt
- Oberfläche **Deutsch / Englisch** umschaltbar, Hell/Dunkel automatisch

## Sicherheitskonzept

| Was | Wie |
|---|---|
| API-Zugangsdaten (Pi-hole, NPM, OIDC-Secret) | **AES-256-GCM** verschlüsselt in SQLite, jeder Wert an sein Feld gebunden. Werden nie an die Oberfläche zurückgegeben. |
| Master-Key Docker | per **Argon2id** aus `PROXYDNS_MASTER_PASSPHRASE` (oder Docker-Secret) abgeleitet; Passphrase und Schlüssel werden nach dem Ableiten im Speicher überschrieben. Hinweis: Eine Umgebungsvariable bleibt per `docker inspect` sichtbar – deshalb ist das Docker-Secret die sicherere Variante. |
| Master-Key Desktop | beim ersten Start zufällig erzeugt, Datei `master.key` mit Rechten `0600` |
| Benutzerpasswörter | **Argon2id** (64 MiB, t=3), min. 12 Zeichen |
| Login-Schutz | 5 Fehlversuche → Konto 15 min gesperrt; zusätzlich IP-Limit; keine Benutzer-Enumeration |
| Sitzungen | zufällige Tokens, in der DB nur als SHA-256-Hash; 30 min Inaktivität / max. 12 h; HttpOnly + SameSite=Strict |
| CSRF | sitzungsgebundenes Token + Pflicht-Header auf allen ändernden Anfragen |
| 2FA (TOTP) | Seed verschlüsselt, Codes nur einmal verwendbar (Replay-Schutz), max. 5 Versuche |
| Verbindung zu Pi-hole/NPM | **nur `https://`**, Zertifikat wird **immer** geprüft (optional eigenes CA-PEM), keine Redirects |
| Domains | optionale Liste erlaubter Domains (z. B. nur `*.home.lan`), strenge Validierung aller Eingaben |
| Erst-Einrichtung (Docker) | Einmal-Code aus dem Container-Log nötig, um den ersten Admin anzulegen |
| Weboberfläche | strikte Content-Security-Policy, kein Inline-Script, kein `innerHTML` |
| Container | distroless, ohne Shell, Non-Root, read-only, ohne Capabilities |

---

## Docker

```bash
cp .env.example .env
# lange Passphrase eintragen, z. B.:  openssl rand -base64 32
nano .env

docker compose up -d --build
docker logs proxydns      # zeigt den Einrichtungscode
```

Dann `http://<server>:8080` öffnen, Einrichtungscode + ersten Admin eingeben.

> **Passphrase gut aufbewahren!** Ohne sie startet die App nicht mehr (die gespeicherten
> Zugangsdaten sind sonst nicht entschlüsselbar).

Statt der Umgebungsvariable kann ein Docker-Secret genutzt werden (nicht per
`docker inspect` sichtbar) – siehe Kommentare in `docker-compose.yml`.

### Notfall-Befehle

```bash
docker exec proxydns proxydns reset-password <benutzer>   # neues Zufallspasswort
docker exec proxydns proxydns reset-mfa <benutzer>        # 2FA abschalten
```

### Wichtige Umgebungsvariablen

| Variable | Standard | Bedeutung |
|---|---|---|
| `PROXYDNS_MASTER_PASSPHRASE` / `PROXYDNS_MASTER_PASSPHRASE_FILE` | – | Master-Passphrase (min. 16 Zeichen) |
| `PROXYDNS_LISTEN` | `0.0.0.0:8080` (Docker) | Adresse/Port |
| `PROXYDNS_TLS_CERT`, `PROXYDNS_TLS_KEY` | – | eigenes HTTPS für die App selbst |
| `PROXYDNS_SECURE_COOKIES` | `false` | `true`, wenn die App hinter HTTPS (z. B. NPM) läuft |
| `PROXYDNS_TRUST_PROXY` | `false` | `X-Forwarded-For` auswerten (nur hinter eigenem Proxy) |
| `PROXYDNS_SESSION_IDLE` / `PROXYDNS_SESSION_MAX` | `30m` / `12h` | Sitzungsdauer |

---

## Desktop (Windows / Linux)

Einfach die Datei starten:

- **Windows:** `proxydns-desktop-windows-amd64.exe` (benötigt WebView2 – bei Windows 10/11 vorinstalliert)
- **Linux:** `proxydns-desktop-linux-amd64` (benötigt WebKitGTK 4.1, bei Arch/CachyOS: `webkit2gtk-4.1`)

Daten liegen im Benutzerprofil:

- Linux: `~/.config/proxydns/`
- Windows: `%AppData%\proxydns\`

Dort liegen `master.key`, `proxydns.db` und `proxydns.log`. **`master.key` sichern** – ohne ihn sind die
gespeicherten Zugangsdaten verloren. OIDC ist in der Desktop-App nicht verfügbar.

---

## Einrichtung von Pi-hole und NPM

### Pi-hole v6
1. *Settings → Web interface / API → Expert*: **App-Passwort** erzeugen.
2. `webserver.api.app_sudo` aktivieren (*Settings → All settings → Webserver and API*),
   sonst darf das App-Passwort keine Einträge anlegen.
3. URL **mit https** eintragen, z. B. `https://pi.hole`.
   Pi-hole nutzt ein selbstsigniertes Zertifikat: Inhalt von `/etc/pihole/tls_ca.crt` ins Feld
   *CA-Zertifikat* kopieren. Der Hostname in der URL muss im Zertifikat stehen
   (Standard: `pi.hole`, änderbar über `webserver.domain`).

### Nginx Proxy Manager
1. Eigenen Benutzer für die App anlegen (ohne 2FA), Rechte: Proxy Hosts verwalten,
   Zertifikate + Access Lists lesen.
2. NPM-Admin-Oberfläche per **HTTPS** erreichbar machen (z. B. NPM als eigenen Proxy-Host
   mit Zertifikat) und diese URL eintragen.
3. **NPM-IP für DNS-Einträge** setzen – auf diese IP zeigen alle neuen Pi-hole-Einträge.

### Empfohlen
*Erlaubte Domains* setzen (z. B. `home.lan`), damit niemand fremde Domains umbiegen kann.

---

## Version & Releases

Die aktuelle Version steht in der Datei [`VERSION`](VERSION) (derzeit `0.0.1-alpha`) und wird beim
Bauen in die Programme übernommen (sichtbar unter *Mein Konto*).

**Release erstellen** (GitHub Actions, [`.github/workflows/release.yml`](.github/workflows/release.yml)):

```bash
echo 0.0.2-alpha > VERSION
git commit -am "Release 0.0.2-alpha"
git push
```

Sobald sich `VERSION` auf `main` ändert, führt der Workflow die Tests aus, baut alle Programme
samt `SHA256SUMS`, veröffentlicht das Docker-Image unter `ghcr.io/<github-benutzer>/proxydns:<version>`,
setzt das Tag `v<version>` und erstellt das GitHub-Release. Gibt es das Tag schon, wird nichts
veröffentlicht. Ein fehlgeschlagenes Release lässt sich unter *Actions → Release → Run workflow*
erneut starten.
Versionen mit Zusatz (`-alpha`, `-beta`, `-rc.1` …) werden als **Pre-release** markiert und setzen
das Docker-Tag `latest` nicht. Bei jedem Push/Pull-Request laufen zusätzlich die Tests
([`ci.yml`](.github/workflows/ci.yml)).

## Selbst bauen

Es wird nur Docker benötigt (kein lokales Go):

```bash
scripts/build.sh test      # Tests
scripts/build.sh server    # dist/proxydns-{linux-amd64,windows-amd64.exe}
scripts/build.sh desktop   # dist/proxydns-desktop-{linux-amd64,windows-amd64.exe}
scripts/build.sh docker    # Image proxydns:latest
scripts/build.sh all
```

## Projektstruktur

```
VERSION                         aktuelle Version (einzige Quelle)
.github/workflows/              CI (Tests) und Release
cmd/proxydns/          Server (Docker / headless) + CLI-Notfallbefehle
cmd/proxydns-desktop/  Desktop-Fenster (Wails)
internal/secure/                Argon2id, AES-GCM, Master-Key
internal/store/                 SQLite: Benutzer, Sitzungen, Einstellungen, Audit-Log
internal/pihole/  internal/npm/ API-Clients
internal/server/                HTTP-API, Auth, Validierung
internal/web/static/            Oberfläche (HTML/CSS/JS, i18n)
```
