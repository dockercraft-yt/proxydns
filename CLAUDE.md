# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

**ProxyDNS Manager** – creates a local DNS record in **Pi-hole v6** (`domain → NPM IP`) and the
matching proxy host in **Nginx Proxy Manager** in one step (with rollback of the DNS record if NPM
fails). One Go codebase, two front-ends:

- **Server mode** (`cmd/proxydns`) – web UI, used in Docker; optional OIDC.
- **Desktop mode** (`cmd/proxydns-desktop`, build tag `desktop`) – Wails window; the HTTP
  handler is served through the WebView asset server, **no network port**, bearer-token auth, no OIDC,
  no setup code.

Status: **ALPHA**. Current version is in `VERSION` (single source of truth).

## Working with the user

- Communicate in **German**. UI texts exist in German and English; code, comments and commit
  messages are English.
- The user is security-conscious: **ask before making design decisions** (architecture, security
  defaults, UX behaviour). Pure implementation details can be decided, but mention notable ones.
- Do not create commits, tags or pushes unless asked.

## Build & test

Go is **not installed locally** – everything runs in Docker:

```bash
scripts/build.sh test      # go vet + go test
scripts/build.sh server    # dist/ headless binaries (linux, windows)
scripts/build.sh desktop   # dist/ desktop binaries (linux via WebKitGTK builder image, windows cross)
scripts/build.sh docker    # image proxydns:latest
```

Ad-hoc Go commands: run them in `golang:1.26-alpine` with the project mounted at `/src` and the
cache volumes `proxydns-gomod` (as `GOPATH=/gopath`) and `proxydns-gocache` (as `GOCACHE`), see `run()` in
`scripts/build.sh`. The desktop package needs CGO + GTK and only builds in `proxydns-desktop-builder`
(`build/desktop-linux.Dockerfile`); `go vet` of that package fails in alpine – that is expected.

Frontend checks (Node is installed locally): `node --check internal/web/static/app.js`.
After changing UI texts, make sure every key exists in **both** `i18n/de.json` and `i18n/en.json`.

## Layout

```
internal/secure   Argon2id password hashing, AES-256-GCM Box (context-bound), master key (keyfile | passphrase)
internal/store    SQLite (modernc, no CGO): users, sessions (token hashes), settings (+encrypted secrets), HMAC-chained audit log
internal/pihole   Pi-hole v6 client (dns.hosts only)
internal/npm      NPM client (proxy hosts, certificates, access lists)
internal/httpx    hardened HTTP client: https only, cert verification always on, optional CA PEM, no redirects
internal/server   HTTP API, auth/session/CSRF, TOTP, OIDC, validation, handlers
internal/web      embedded frontend (vanilla JS, no build step)
```

## Security rules (do not weaken)

- Secrets (API passwords, client secret, TOTP seeds) are stored **only** via `store.SaveSettings` /
  `SealUserSecret` (AES-GCM with a context string). Never return them to the client, never log them.
- Backend URLs must be `https://`; never add an "insecure skip verify" option (user decision).
- Every state-changing API call needs header `X-ProxyDNS-Request: 1`; authenticated ones additionally the
  session `X-CSRF-Token` (server mode).
- Validation returns stable **error codes** (`writeError(w, status, "code", detail)`); each code needs
  a translation `err.<code>` in both i18n files.
- New audit actions need `audit.action.<name>` translations.
- Frontend: build DOM only with `h()` / `mount()` and `textContent` – **no `innerHTML`**, no inline
  scripts or styles (strict CSP). Use `mount(el, …)` instead of `el.replaceChildren(…)` when children
  can be `null`/arrays.
- Raw nginx config (`advancedConfig`) is admin-only.
- JSON lists sent to the frontend must be non-nil slices (`[]`, never `null`).

## Backend quirks (learned in testing)

- Pi-hole v6: an app password works only after clicking **"Enable new app password"**; creating
  records with an app password requires `webserver.api.app_sudo = true`. A failed login returns 401
  with the reason in `session.message`, not `error.message`.
- NPM: older versions return booleans as `0/1` and IDs as strings → use `npm.Bool` / `npm.Int`.
  API users must not have 2FA (`requires_2fa`).

## Release

1. Set the new version in `VERSION` (e.g. `0.0.2-alpha`).
2. Commit and push to `main` → `.github/workflows/release.yml` runs because `VERSION` changed. If tag
   `v<VERSION>` does not exist yet, it runs tests, builds all binaries + `SHA256SUMS`, pushes
   `ghcr.io/<owner>/proxydns:<version>`, then creates the tag and the GitHub release. Never tag by hand.
3. Versions with a suffix (`-alpha`, `-beta`, …) become a **pre-release** and do not update `latest`.
