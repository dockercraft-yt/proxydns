package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"proxydns/internal/secure"
	"proxydns/internal/store"
)

type authLevel int

const (
	levelAny     authLevel = iota // any session, including MFA pending
	levelPending                  // only sessions waiting for the TOTP code
	levelUser                     // fully authenticated
	levelAdmin                    // fully authenticated admin
)

// pendingSessionLifetime is how long a user has to enter the TOTP code.
const pendingSessionLifetime = 5 * time.Minute

var errNoSession = errors.New("no valid session")

type authCtx struct {
	user *store.User
	sess *store.Session
}

type authedHandler func(w http.ResponseWriter, r *http.Request, a *authCtx)

// requireConfigured blocks a handler with 409 "setup_incomplete" until Pi-hole
// and NPM are configured (setup mode).
func (s *Server) requireConfigured(h authedHandler) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, a *authCtx) {
		ok, err := s.backendsConfigured()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		if !ok {
			writeError(w, http.StatusConflict, "setup_incomplete")
			return
		}
		h(w, r, a)
	}
}

// auth wraps a handler with session validation, authorisation and the
// session-bound CSRF token check for state-changing requests.
func (s *Server) auth(level authLevel, h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, user, err := s.loadSession(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		switch level {
		case levelPending:
			if !sess.MFAPending {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
		case levelUser, levelAdmin:
			if sess.MFAPending {
				writeError(w, http.StatusUnauthorized, "mfa_required")
				return
			}
			if level == levelAdmin && !user.IsAdmin() {
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}
		}
		// Desktop mode uses a bearer token that the browser never sends
		// automatically, so CSRF is impossible there.
		if !s.desktop() && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !secure.Equal(r.Header.Get("X-CSRF-Token"), sess.CSRF) {
				writeError(w, http.StatusForbidden, "csrf")
				return
			}
		}
		h(w, r, &authCtx{user: user, sess: sess})
	}
}

func (s *Server) cookieSecure() bool { return s.cfg.SecureCookies || s.cfg.TLSEnabled() }

func (s *Server) cookieName() string {
	if s.cookieSecure() {
		return "__Host-proxydns_session"
	}
	return "proxydns_session"
}

func (s *Server) sessionToken(r *http.Request) string {
	if s.desktop() {
		auth := r.Header.Get("Authorization")
		if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return after
		}
		return ""
	}
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *Server) loadSession(r *http.Request) (*store.Session, *store.User, error) {
	tok := s.sessionToken(r)
	if tok == "" || len(tok) > 128 {
		return nil, nil, errNoSession
	}
	sess, err := s.store.GetSession(secure.HashToken(tok))
	if err != nil {
		return nil, nil, errNoSession
	}
	now := time.Now().Unix()
	if now >= sess.ExpiresAt || now-sess.LastSeen > int64(s.cfg.SessionIdle.Seconds()) {
		_ = s.store.DeleteSession(sess.IDHash)
		return nil, nil, errNoSession
	}
	user, err := s.store.GetUserByID(sess.UserID)
	if err != nil || user.Disabled {
		_ = s.store.DeleteSession(sess.IDHash)
		return nil, nil, errNoSession
	}
	if now-sess.LastSeen >= 60 {
		_ = s.store.TouchSession(sess.IDHash, now)
	}
	return sess, user, nil
}

// startSession creates a session and sets the cookie (server mode). It
// returns the raw token, which is only needed in desktop mode.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, user *store.User, mfaPending bool) (*store.Session, string, error) {
	raw, err := secure.RandomToken(32)
	if err != nil {
		return nil, "", err
	}
	csrf, err := secure.RandomToken(32)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	lifetime := s.cfg.SessionMax
	if mfaPending {
		lifetime = pendingSessionLifetime
	}
	ua := r.UserAgent()
	if len(ua) > 256 {
		ua = ua[:256]
	}
	sess := &store.Session{
		IDHash:     secure.HashToken(raw),
		UserID:     user.ID,
		CSRF:       csrf,
		MFAPending: mfaPending,
		CreatedAt:  now.Unix(),
		LastSeen:   now.Unix(),
		ExpiresAt:  now.Add(lifetime).Unix(),
		IP:         s.clientIP(r),
		UserAgent:  ua,
	}
	if err := s.store.CreateSession(sess); err != nil {
		return nil, "", err
	}
	if !s.desktop() {
		http.SetCookie(w, &http.Cookie{
			Name:     s.cookieName(),
			Value:    raw,
			Path:     "/",
			HttpOnly: true,
			Secure:   s.cookieSecure(),
			SameSite: http.SameSiteStrictMode,
		})
	}
	return sess, raw, nil
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	if s.desktop() {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cookieSecure(),
		SameSite: http.SameSiteStrictMode,
	})
}

// audit writes an audit log entry; failures are logged but do not abort the request.
func (s *Server) audit(r *http.Request, user *store.User, action, target string, success bool, details string) {
	e := store.AuditEntry{
		IP:      s.clientIP(r),
		Action:  action,
		Target:  target,
		Success: success,
		Details: details,
	}
	if s.desktop() {
		e.IP = "local"
	}
	if user != nil {
		e.UserID = user.ID
		e.Username = user.Username
	}
	if err := s.store.AddAudit(e); err != nil {
		s.log.Error("audit log write failed", "action", action, "err", err)
	}
}
