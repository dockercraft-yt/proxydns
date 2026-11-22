package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"proxydns/internal/secure"
	"proxydns/internal/store"
)

const (
	oidcFlowLifetime = 10 * time.Minute
	oidcStateCookie  = "proxydns_oidc_state"
	oidcCallbackPath = "/api/auth/oidc/callback"
)

type oidcFlow struct {
	nonce    string
	verifier string
	expires  time.Time
}

type oidcClient struct {
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// oidcManager caches the discovered provider and tracks running logins.
type oidcManager struct {
	mu     sync.Mutex
	cached *oidcClient
	flows  map[string]oidcFlow
}

func newOIDCManager() *oidcManager {
	return &oidcManager{flows: map[string]oidcFlow{}}
}

// reset drops the cached provider (called when settings change).
func (m *oidcManager) reset() {
	m.mu.Lock()
	m.cached = nil
	m.mu.Unlock()
}

func (m *oidcManager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, f := range m.flows {
		if now.After(f.expires) {
			delete(m.flows, k)
		}
	}
}

func (m *oidcManager) client(ctx context.Context, s *Server, st *appSettings) (*oidcClient, error) {
	m.mu.Lock()
	if m.cached != nil {
		c := m.cached
		m.mu.Unlock()
		return c, nil
	}
	m.mu.Unlock()

	if st.OIDCIssuer == "" || st.OIDCClientID == "" || st.OIDCRedirectURL == "" {
		return nil, errNotConfigured
	}
	secret, err := s.store.Secret(kOIDCClientSecret)
	if err != nil {
		return nil, err
	}
	provider, err := oidc.NewProvider(ctx, st.OIDCIssuer)
	if err != nil {
		return nil, err
	}
	c := &oidcClient{
		provider: provider,
		oauth: &oauth2.Config{
			ClientID:     st.OIDCClientID,
			ClientSecret: secret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  st.OIDCRedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: st.OIDCClientID}),
	}
	m.mu.Lock()
	m.cached = c
	m.mu.Unlock()
	return c, nil
}

func (m *oidcManager) addFlow(state string, f oidcFlow) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.flows) > 1000 { // bound memory use
		for k := range m.flows {
			delete(m.flows, k)
			break
		}
	}
	m.flows[state] = f
}

func (m *oidcManager) takeFlow(state string) (oidcFlow, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.flows[state]
	delete(m.flows, state)
	if !ok || time.Now().After(f.expires) {
		return oidcFlow{}, false
	}
	return f, true
}

func (s *Server) oidcFail(w http.ResponseWriter, r *http.Request, user *store.User, reason, code string) {
	s.audit(r, user, "login_oidc", "", false, reason)
	http.Redirect(w, r, "/#/login?error="+code, http.StatusFound)
}

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	st, err := s.loadSettings()
	if err != nil || !st.OIDCEnabled {
		http.Redirect(w, r, "/#/login?error=oidc_disabled", http.StatusFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendTimeout)
	defer cancel()
	c, err := s.oidc.client(ctx, s, st)
	if err != nil {
		s.log.Warn("OIDC provider unavailable", "err", err)
		s.oidcFail(w, r, nil, "provider unavailable: "+err.Error(), "oidc_failed")
		return
	}
	state, err1 := secure.RandomToken(32)
	nonce, err2 := secure.RandomToken(32)
	if err1 != nil || err2 != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	verifier := oauth2.GenerateVerifier()
	s.oidc.addFlow(state, oidcFlow{nonce: nonce, verifier: verifier, expires: time.Now().Add(oidcFlowLifetime)})

	// Binds the flow to this browser. SameSite=Lax is required because the
	// IdP redirects back with a cross-site top-level navigation.
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    state,
		Path:     oidcCallbackPath,
		MaxAge:   int(oidcFlowLifetime.Seconds()),
		HttpOnly: true,
		Secure:   s.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, c.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: oidcCallbackPath, MaxAge: -1, HttpOnly: true, Secure: s.cookieSecure(), SameSite: http.SameSiteLaxMode})

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.oidcFail(w, r, nil, "IdP error: "+truncate(e, 100), "oidc_failed")
		return
	}
	state := q.Get("state")
	cookie, err := r.Cookie(oidcStateCookie)
	if state == "" || err != nil || !secure.Equal(cookie.Value, state) {
		s.oidcFail(w, r, nil, "state mismatch", "oidc_failed")
		return
	}
	flow, ok := s.oidc.takeFlow(state)
	if !ok {
		s.oidcFail(w, r, nil, "unknown or expired state", "oidc_failed")
		return
	}
	st, err := s.loadSettings()
	if err != nil || !st.OIDCEnabled {
		s.oidcFail(w, r, nil, "OIDC disabled", "oidc_disabled")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendTimeout)
	defer cancel()
	c, err := s.oidc.client(ctx, s, st)
	if err != nil {
		s.oidcFail(w, r, nil, "provider unavailable", "oidc_failed")
		return
	}
	tok, err := c.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(flow.verifier))
	if err != nil {
		s.oidcFail(w, r, nil, "code exchange failed: "+truncate(err.Error(), 200), "oidc_failed")
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		s.oidcFail(w, r, nil, "no id_token", "oidc_failed")
		return
	}
	idt, err := c.verifier.Verify(ctx, rawID)
	if err != nil || !secure.Equal(idt.Nonce, flow.nonce) {
		s.oidcFail(w, r, nil, "invalid id_token", "oidc_failed")
		return
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := idt.Claims(&claims); err != nil {
		s.oidcFail(w, r, nil, "invalid claims", "oidc_failed")
		return
	}

	user, err := s.resolveOIDCUser(idt.Subject, claims.Email, claims.EmailVerified)
	if err != nil {
		s.oidcFail(w, r, nil, err.Error()+" (sub="+truncate(idt.Subject, 64)+", email="+truncate(claims.Email, 100)+")", "oidc_no_user")
		return
	}
	if user.Disabled {
		s.oidcFail(w, r, user, "account disabled", "oidc_no_user")
		return
	}
	if _, _, err := s.startSession(w, r, user, false); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.audit(r, user, "login_oidc", user.Username, true, "")
	http.Redirect(w, r, "/#/entries", http.StatusFound)
}

// resolveOIDCUser maps an OIDC identity to a pre-created local user:
// first by a previously linked subject, otherwise by verified e-mail (which
// then links the subject). Unknown identities are rejected.
func (s *Server) resolveOIDCUser(subject, email string, emailVerified *bool) (*store.User, error) {
	if subject == "" {
		return nil, errors.New("missing subject")
	}
	u, err := s.store.GetUserByOIDCSubject(subject)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, errors.New("no linked user and no e-mail claim")
	}
	if emailVerified == nil || !*emailVerified {
		return nil, errors.New("e-mail not verified by IdP")
	}
	users, err := s.store.FindUsersByEmail(email)
	if err != nil {
		return nil, err
	}
	if len(users) != 1 {
		return nil, errors.New("no unique local user with this e-mail")
	}
	u = users[0]
	if u.OIDCSubject != "" {
		return nil, errors.New("user is linked to a different OIDC identity")
	}
	u.OIDCSubject = subject
	if err := s.store.UpdateUser(u); err != nil {
		return nil, err
	}
	return u, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
