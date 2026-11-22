# Contributing to ProxyDNS Manager

Thanks for your interest! The project is in **alpha** – issues and pull requests are welcome.
Code, comments and commit messages are in English; the UI exists in German and English.

## Building

Only Docker is required – Go does not need to be installed locally:

```bash
scripts/build.sh test      # go vet + go test
scripts/build.sh server    # dist/proxydns-{linux-amd64,windows-amd64.exe}
scripts/build.sh desktop   # dist/proxydns-desktop-{linux-amd64,windows-amd64.exe}
scripts/build.sh docker    # image proxydns:latest
scripts/build.sh all
```

The desktop build needs CGO and GTK and therefore runs in its own builder image
(`build/desktop-linux.Dockerfile`).

Frontend check (Node): `node --check internal/web/static/app.js`

## Screenshots

The README screenshots in `docs/screenshots/` are generated, not taken by hand:

```bash
scripts/screenshots/screenshots.sh
```

The script serves the UI with a mock API (`scripts/screenshots/mock.py`, example data under
`home.example.org`, listens on `127.0.0.1:8765` only) and captures every page in German/English and
light/dark with headless Chromium. Requirements: `python3` and `chromium` (or set `CHROMIUM=…`).
If the API changes, update the example responses in `mock.py` accordingly.

## Project layout

```
VERSION                         current version (single source of truth)
.github/workflows/              CI (tests) and release
cmd/proxydns/                   server (Docker / headless) + CLI emergency commands
cmd/proxydns-desktop/           desktop window (Wails, build tag "desktop")
internal/secure/                Argon2id, AES-GCM, master key
internal/store/                 SQLite: users, sessions, settings, audit log
internal/pihole/  internal/npm/ API clients
internal/httpx/                 hardened HTTP client (https only, no redirects)
internal/server/                HTTP API, auth, validation
internal/web/static/            UI (HTML/CSS/JS without build step, i18n)
docs/screenshots/               README screenshots (light/dark, de/en)
scripts/screenshots/            generator for the README screenshots
```

## Guidelines

- **Do not weaken the security model.** In particular: secrets are stored only encrypted and never
  returned to the client or logged; backend URLs stay `https://` with certificate verification
  (no "insecure skip verify" option).
- Every state-changing API call requires the header `X-ProxyDNS-Request: 1` (plus the CSRF token
  when logged in).
- API errors use stable error codes; each code needs a translation `err.<code>` in
  **both** `i18n/de.json` and `i18n/en.json`. The same applies to new UI texts and audit actions
  (`audit.action.<name>`).
- Frontend: build the DOM only via `h()` / `mount()` and `textContent` – no `innerHTML`, no inline
  scripts or styles (strict CSP).

## Versioning & releases

The current version is in [`VERSION`](VERSION) and is compiled into the binaries (visible under
*My account*).

A release is created by GitHub Actions ([`release.yml`](.github/workflows/release.yml)) as soon as
`VERSION` changes on `main`:

```bash
echo 0.0.2-alpha > VERSION
git commit -am "Release 0.0.2-alpha"
git push
```

The workflow runs the tests, builds all binaries including `SHA256SUMS`, publishes the Docker image
`ghcr.io/<owner>/proxydns:<version>`, creates the tag `v<version>` and the GitHub release. If the
tag already exists, nothing is published. A failed release can be restarted under
*Actions → Release → Run workflow*. Do not create tags by hand.

Versions with a suffix (`-alpha`, `-beta`, `-rc.1` …) are marked as **pre-release** and do not
update the Docker tag `latest`. Additionally, tests run on every push and pull request
([`ci.yml`](.github/workflows/ci.yml)).
