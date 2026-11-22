// Package server implements the HTTP API and serves the embedded frontend.
// The same handler is used by the web server (Docker) and the desktop
// window (Wails asset server, no network listener).
package server

import (
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"proxydns/internal/config"
	"proxydns/internal/store"
	"proxydns/internal/web"
)

const maxRequestBody = 1 << 20

// Server holds the application state.
type Server struct {
	cfg     *config.Config
	store   *store.Store
	log     *slog.Logger
	version string

	setupMu    sync.Mutex
	setupToken string

	loginLimiter *failureLimiter
	entryMu      sync.Mutex // serialises entry creation (check + create + rollback)

	oidc *oidcManager

	stopOnce sync.Once
	stop     chan struct{}
}

// New creates the server and starts background maintenance.
func New(cfg *config.Config, st *store.Store, logger *slog.Logger, version string) *Server {
	s := &Server{
		cfg:          cfg,
		store:        st,
		log:          logger,
		version:      version,
		loginLimiter: newFailureLimiter(10, 15*time.Minute),
		oidc:         newOIDCManager(),
		stop:         make(chan struct{}),
	}
	go s.maintenance()
	return s
}

// Close stops background tasks.
func (s *Server) Close() { s.stopOnce.Do(func() { close(s.stop) }) }

// SetSetupToken sets the one-time token required to create the first admin
// (server mode only).
func (s *Server) SetSetupToken(token string) {
	s.setupMu.Lock()
	s.setupToken = token
	s.setupMu.Unlock()
}

func (s *Server) desktop() bool { return s.cfg.Mode == config.ModeDesktop }

func (s *Server) maintenance() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			now := time.Now()
			if err := s.store.DeleteExpiredSessions(now.Unix(), now.Add(-s.cfg.SessionIdle).Unix()); err != nil {
				s.log.Warn("session cleanup failed", "err", err)
			}
			s.loginLimiter.Cleanup()
			s.oidc.cleanup()
		}
	}
}

// Handler returns the complete HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /", s.staticHandler())

	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/info", s.handleInfo)
	mux.HandleFunc("POST /api/setup", s.handleSetup)

	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/totp", s.auth(levelPending, s.handleLoginTOTP))
	mux.HandleFunc("POST /api/auth/logout", s.auth(levelAny, s.handleLogout))
	mux.HandleFunc("GET /api/auth/me", s.auth(levelUser, s.handleMe))
	if !s.desktop() {
		mux.HandleFunc("GET /api/auth/oidc/start", s.handleOIDCStart)
		mux.HandleFunc("GET /api/auth/oidc/callback", s.handleOIDCCallback)
	}

	mux.HandleFunc("POST /api/account/password", s.auth(levelUser, s.requireConfigured(s.handleChangePassword)))
	mux.HandleFunc("POST /api/account/totp/setup", s.auth(levelUser, s.requireConfigured(s.handleTOTPSetup)))
	mux.HandleFunc("POST /api/account/totp/enable", s.auth(levelUser, s.requireConfigured(s.handleTOTPEnable)))
	mux.HandleFunc("POST /api/account/totp/disable", s.auth(levelUser, s.requireConfigured(s.handleTOTPDisable)))

	mux.HandleFunc("GET /api/entries", s.auth(levelUser, s.requireConfigured(s.handleListEntries)))
	mux.HandleFunc("GET /api/entries/options", s.auth(levelUser, s.requireConfigured(s.handleEntryOptions)))
	mux.HandleFunc("POST /api/entries", s.auth(levelUser, s.requireConfigured(s.handleCreateEntry)))

	mux.HandleFunc("GET /api/settings", s.auth(levelAdmin, s.handleGetSettings))
	mux.HandleFunc("PUT /api/settings", s.auth(levelAdmin, s.handleSaveSettings))
	mux.HandleFunc("POST /api/settings/test/{target}", s.auth(levelAdmin, s.handleTestSettings))

	mux.HandleFunc("GET /api/users", s.auth(levelAdmin, s.requireConfigured(s.handleListUsers)))
	mux.HandleFunc("POST /api/users", s.auth(levelAdmin, s.requireConfigured(s.handleCreateUser)))
	mux.HandleFunc("PUT /api/users/{id}", s.auth(levelAdmin, s.requireConfigured(s.handleUpdateUser)))
	mux.HandleFunc("DELETE /api/users/{id}", s.auth(levelAdmin, s.requireConfigured(s.handleDeleteUser)))
	mux.HandleFunc("POST /api/users/{id}/reset-mfa", s.auth(levelAdmin, s.requireConfigured(s.handleResetUserMFA)))
	mux.HandleFunc("POST /api/users/{id}/unlink-oidc", s.auth(levelAdmin, s.requireConfigured(s.handleUnlinkOIDC)))

	mux.HandleFunc("GET /api/audit", s.auth(levelAdmin, s.requireConfigured(s.handleListAudit)))
	mux.HandleFunc("GET /api/audit/verify", s.auth(levelAdmin, s.requireConfigured(s.handleVerifyAudit)))

	return s.securityHeaders(s.requestGuard(mux))
}

func (s *Server) staticHandler() http.Handler {
	files := web.Static()
	fileServer := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		// No directory listings.
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/" {
			if _, err := fs.Stat(files, strings.TrimPrefix(r.URL.Path, "/")); err != nil {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, r)
	})
}

// securityHeaders sets a strict CSP and related headers on every response.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if s.cfg.TLSEnabled() {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// requestGuard limits body size and requires the custom header
// X-ProxyDNS-Request on all state-changing API calls. Browsers cannot send custom
// headers cross-origin without a CORS preflight (which this server never
// approves), so this blocks CSRF even on endpoints without a session
// (login, setup).
func (s *Server) requestGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		if r.Method != http.MethodGet && r.Method != http.MethodHead && strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("X-ProxyDNS-Request") != "1" {
				writeError(w, http.StatusForbidden, "csrf")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
