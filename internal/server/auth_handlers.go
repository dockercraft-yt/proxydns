package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"proxydns/internal/secure"
	"proxydns/internal/store"
)

// Account lockout policy.
const (
	maxFailedLogins = 5
	lockoutDuration = 15 * time.Minute
	maxTOTPAttempts = 5
)

type userDTO struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	Email       string `json:"email"`
	HasPassword bool   `json:"hasPassword"`
	TOTPEnabled bool   `json:"totpEnabled"`
	OIDCLinked  bool   `json:"oidcLinked"`
	Disabled    bool   `json:"disabled"`
	Locked      bool   `json:"locked"`
	CreatedAt   int64  `json:"createdAt"`
}

func toUserDTO(u *store.User) userDTO {
	return userDTO{
		ID:          u.ID,
		Username:    u.Username,
		Role:        u.Role,
		Email:       u.Email,
		HasPassword: u.PasswordHash != "",
		TOTPEnabled: u.TOTPEnabled,
		OIDCLinked:  u.OIDCSubject != "",
		Disabled:    u.Disabled,
		Locked:      u.LockedUntil > time.Now().Unix(),
		CreatedAt:   u.CreatedAt,
	}
}

type meResponse struct {
	User        *userDTO `json:"user,omitempty"`
	CSRF        string   `json:"csrf,omitempty"`
	Token       string   `json:"token,omitempty"` // desktop mode only
	MFARequired bool     `json:"mfaRequired,omitempty"`
	// Configured is false while Pi-hole/NPM are not set up (setup mode).
	Configured bool `json:"configured,omitempty"`
}

func (s *Server) meFor(u *store.User, sess *store.Session, rawToken string) meResponse {
	dto := toUserDTO(u)
	resp := meResponse{User: &dto, CSRF: sess.CSRF}
	resp.Configured, _ = s.backendsConfigured()
	if s.desktop() {
		resp.Token = rawToken
	}
	return resp
}

// handleInfo returns everything the frontend needs before login.
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	resp := map[string]any{
		"mode":           s.cfg.Mode,
		"version":        s.version,
		"setupRequired":  n == 0,
		"setupNeedsCode": n == 0 && !s.desktop(),
		"oidc":           map[string]any{"enabled": false},
	}
	if !s.desktop() {
		if st, err := s.loadSettings(); err == nil && st.OIDCEnabled {
			resp["oidc"] = map[string]any{"enabled": true, "label": st.OIDCButtonLabel}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSetup creates the first admin account.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.loginLimiter.Allowed(ip) {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	var in struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	n, err := s.store.CountUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if n > 0 {
		writeError(w, http.StatusConflict, "setup_done")
		return
	}
	if !s.desktop() && (s.setupToken == "" || !secure.Equal(strings.TrimSpace(in.Token), s.setupToken)) {
		s.loginLimiter.Fail(ip)
		s.audit(r, nil, "setup", in.Username, false, "invalid setup code")
		writeError(w, http.StatusUnauthorized, "invalid_setup_token")
		return
	}
	username := strings.TrimSpace(in.Username)
	if code := validateUsername(username); code != "" {
		writeError(w, http.StatusBadRequest, code)
		return
	}
	if code := validatePassword(in.Password); code != "" {
		writeError(w, http.StatusBadRequest, code)
		return
	}
	hash, err := secure.HashPassword(in.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	user := &store.User{Username: username, PasswordHash: hash, Role: store.RoleAdmin}
	if err := s.store.CreateUser(user); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.setupToken = ""
	s.audit(r, user, "setup", username, true, "first admin created")
	sess, raw, err := s.startSession(w, r, user, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, s.meFor(user, sess, raw))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.loginLimiter.Allowed(ip) {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	username := strings.TrimSpace(in.Username)
	if len(username) > 64 || len(in.Password) > 1024 {
		writeError(w, http.StatusBadRequest, "invalid_credentials")
		return
	}

	user, err := s.store.GetUserByUsername(username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if user == nil || user.PasswordHash == "" {
		secure.DummyVerify(in.Password)
		s.loginLimiter.Fail(ip)
		s.audit(r, nil, "login", username, false, "unknown user or no password")
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if user.LockedUntil > time.Now().Unix() {
		s.loginLimiter.Fail(ip)
		s.audit(r, user, "login", username, false, "account locked")
		writeError(w, http.StatusUnauthorized, "account_locked")
		return
	}
	ok, err := secure.VerifyPassword(in.Password, user.PasswordHash)
	if err != nil {
		s.log.Error("password verification error", "user", user.Username, "err", err)
	}
	if !ok {
		s.loginLimiter.Fail(ip)
		locked, _ := s.store.RegisterFailedLogin(user.ID, maxFailedLogins, lockoutDuration)
		detail := "wrong password"
		if locked {
			detail = "wrong password, account locked"
		}
		s.audit(r, user, "login", username, false, detail)
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if user.Disabled {
		s.audit(r, user, "login", username, false, "account disabled")
		writeError(w, http.StatusUnauthorized, "account_disabled")
		return
	}
	_ = s.store.ResetFailedLogins(user.ID)

	sess, raw, err := s.startSession(w, r, user, user.TOTPEnabled)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if user.TOTPEnabled {
		resp := meResponse{MFARequired: true, CSRF: sess.CSRF}
		if s.desktop() {
			resp.Token = raw
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	s.audit(r, user, "login", username, true, "password")
	writeJSON(w, http.StatusOK, s.meFor(user, sess, raw))
}

func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	attempts, err := s.store.IncrementMFAAttempts(a.sess.IDHash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if attempts > maxTOTPAttempts {
		_ = s.store.DeleteSession(a.sess.IDHash)
		s.clearSessionCookie(w)
		s.audit(r, a.user, "login", a.user.Username, false, "too many TOTP attempts")
		writeError(w, http.StatusUnauthorized, "mfa_too_many")
		return
	}
	if !s.checkUserTOTP(a.user, a.user.TOTPSecret, in.Code) {
		s.audit(r, a.user, "login", a.user.Username, false, "wrong TOTP code")
		writeError(w, http.StatusUnauthorized, "invalid_code")
		return
	}
	// Replace the pending session with a full one (session fixation protection).
	_ = s.store.DeleteSession(a.sess.IDHash)
	sess, raw, err := s.startSession(w, r, a.user, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.audit(r, a.user, "login", a.user.Username, true, "password + TOTP")
	writeJSON(w, http.StatusOK, s.meFor(a.user, sess, raw))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, a *authCtx) {
	_ = s.store.DeleteSession(a.sess.IDHash)
	s.clearSessionCookie(w)
	if !a.sess.MFAPending {
		s.audit(r, a.user, "logout", a.user.Username, true, "")
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, a *authCtx) {
	// The raw token is not returned again; the desktop client keeps it in memory.
	writeJSON(w, http.StatusOK, s.meFor(a.user, a.sess, ""))
}
