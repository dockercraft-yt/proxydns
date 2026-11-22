package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"proxydns/internal/httpx"
	"proxydns/internal/npm"
	"proxydns/internal/pihole"
)

// Setting keys.
const (
	kPiholeURL        = "pihole.url"
	kPiholePassword   = "pihole.password" // secret
	kPiholeCA         = "pihole.ca_pem"
	kNPMURL           = "npm.url"
	kNPMEmail         = "npm.email"
	kNPMPassword      = "npm.password" // secret
	kNPMCA            = "npm.ca_pem"
	kNPMTargetIP      = "npm.target_ip"
	kAllowedDomains   = "entries.allowed_domains"
	kOIDCEnabled      = "oidc.enabled"
	kOIDCIssuer       = "oidc.issuer"
	kOIDCClientID     = "oidc.client_id"
	kOIDCClientSecret = "oidc.client_secret" // secret
	kOIDCRedirectURL  = "oidc.redirect_url"
	kOIDCButtonLabel  = "oidc.button_label"
	// kVerified is "true" once Pi-hole and NPM settings were saved after a
	// successful connection check. Without it the app stays in setup mode.
	kVerified = "setup.verified"
)

const backendTimeout = 30 * time.Second

// appSettings is the non-secret part of the configuration.
type appSettings struct {
	PiholeURL       string
	PiholeCA        string
	NPMURL          string
	NPMEmail        string
	NPMCA           string
	NPMTargetIP     string
	AllowedDomains  []string
	OIDCEnabled     bool
	OIDCIssuer      string
	OIDCClientID    string
	OIDCRedirectURL string
	OIDCButtonLabel string
	Verified        bool
}

func (s *Server) loadSettings() (*appSettings, error) {
	m, err := s.store.Settings()
	if err != nil {
		return nil, err
	}
	allowed, _ := parseDomainList(m[kAllowedDomains])
	return &appSettings{
		PiholeURL:       m[kPiholeURL],
		PiholeCA:        m[kPiholeCA],
		NPMURL:          m[kNPMURL],
		NPMEmail:        m[kNPMEmail],
		NPMCA:           m[kNPMCA],
		NPMTargetIP:     m[kNPMTargetIP],
		AllowedDomains:  allowed,
		OIDCEnabled:     m[kOIDCEnabled] == "true",
		OIDCIssuer:      m[kOIDCIssuer],
		OIDCClientID:    m[kOIDCClientID],
		OIDCRedirectURL: m[kOIDCRedirectURL],
		OIDCButtonLabel: m[kOIDCButtonLabel],
		Verified:        m[kVerified] == "true",
	}, nil
}

var errNotConfigured = errors.New("not configured")

// backendsConfigured reports whether all required Pi-hole and NPM settings
// are stored. Until then the application is in setup mode: only auth,
// account and settings endpoints are usable.
func (s *Server) backendsConfigured() (bool, error) {
	st, err := s.loadSettings()
	if err != nil {
		return false, err
	}
	if !st.Verified || st.PiholeURL == "" || st.NPMURL == "" || st.NPMEmail == "" || st.NPMTargetIP == "" {
		return false, nil
	}
	for _, k := range []string{kPiholePassword, kNPMPassword} {
		ok, err := s.store.HasSecret(k)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func (s *Server) piholeClient(st *appSettings) (*pihole.Client, error) {
	pw, err := s.store.Secret(kPiholePassword)
	if err != nil {
		return nil, err
	}
	return newPiholeClient(st.PiholeURL, pw, st.PiholeCA)
}

func newPiholeClient(baseURL, pw, caPEM string) (*pihole.Client, error) {
	if baseURL == "" || pw == "" {
		return nil, errNotConfigured
	}
	hc, err := httpx.NewClient(caPEM, backendTimeout)
	if err != nil {
		return nil, err
	}
	return pihole.New(baseURL, pw, hc)
}

func (s *Server) npmClient(st *appSettings) (*npm.Client, error) {
	pw, err := s.store.Secret(kNPMPassword)
	if err != nil {
		return nil, err
	}
	return newNPMClient(st.NPMURL, st.NPMEmail, pw, st.NPMCA)
}

func newNPMClient(baseURL, email, pw, caPEM string) (*npm.Client, error) {
	if baseURL == "" || email == "" || pw == "" {
		return nil, errNotConfigured
	}
	hc, err := httpx.NewClient(caPEM, backendTimeout)
	if err != nil {
		return nil, err
	}
	return npm.New(baseURL, email, pw, hc)
}

type settingsDTO struct {
	PiholeURL           string `json:"piholeUrl"`
	PiholePasswordSet   bool   `json:"piholePasswordSet"`
	PiholeCA            string `json:"piholeCaPem"`
	NPMURL              string `json:"npmUrl"`
	NPMEmail            string `json:"npmEmail"`
	NPMPasswordSet      bool   `json:"npmPasswordSet"`
	NPMCA               string `json:"npmCaPem"`
	NPMTargetIP         string `json:"npmTargetIp"`
	AllowedDomains      string `json:"allowedDomains"`
	OIDCAvailable       bool   `json:"oidcAvailable"`
	OIDCEnabled         bool   `json:"oidcEnabled"`
	OIDCIssuer          string `json:"oidcIssuer"`
	OIDCClientID        string `json:"oidcClientId"`
	OIDCClientSecretSet bool   `json:"oidcClientSecretSet"`
	OIDCRedirectURL     string `json:"oidcRedirectUrl"`
	OIDCButtonLabel     string `json:"oidcButtonLabel"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request, a *authCtx) {
	st, err := s.loadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	dto := settingsDTO{
		PiholeURL:       st.PiholeURL,
		PiholeCA:        st.PiholeCA,
		NPMURL:          st.NPMURL,
		NPMEmail:        st.NPMEmail,
		NPMCA:           st.NPMCA,
		NPMTargetIP:     st.NPMTargetIP,
		AllowedDomains:  strings.Join(st.AllowedDomains, ", "),
		OIDCAvailable:   !s.desktop(),
		OIDCEnabled:     st.OIDCEnabled,
		OIDCIssuer:      st.OIDCIssuer,
		OIDCClientID:    st.OIDCClientID,
		OIDCRedirectURL: st.OIDCRedirectURL,
		OIDCButtonLabel: st.OIDCButtonLabel,
	}
	dto.PiholePasswordSet, _ = s.store.HasSecret(kPiholePassword)
	dto.NPMPasswordSet, _ = s.store.HasSecret(kNPMPassword)
	dto.OIDCClientSecretSet, _ = s.store.HasSecret(kOIDCClientSecret)
	writeJSON(w, http.StatusOK, dto)
}

type settingsUpdate struct {
	PiholeURL        string  `json:"piholeUrl"`
	PiholePassword   *string `json:"piholePassword"`
	PiholeCA         string  `json:"piholeCaPem"`
	NPMURL           string  `json:"npmUrl"`
	NPMEmail         string  `json:"npmEmail"`
	NPMPassword      *string `json:"npmPassword"`
	NPMCA            string  `json:"npmCaPem"`
	NPMTargetIP      string  `json:"npmTargetIp"`
	AllowedDomains   string  `json:"allowedDomains"`
	OIDCEnabled      bool    `json:"oidcEnabled"`
	OIDCIssuer       string  `json:"oidcIssuer"`
	OIDCClientID     string  `json:"oidcClientId"`
	OIDCClientSecret *string `json:"oidcClientSecret"`
	OIDCRedirectURL  string  `json:"oidcRedirectUrl"`
	OIDCButtonLabel  string  `json:"oidcButtonLabel"`
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in settingsUpdate
	if !decodeJSON(w, r, &in) {
		return
	}
	trim := func(p *string) {
		if p != nil {
			*p = strings.TrimSpace(*p)
		}
	}
	in.PiholeURL = strings.TrimSpace(in.PiholeURL)
	in.NPMURL = strings.TrimSpace(in.NPMURL)
	in.NPMEmail = strings.TrimSpace(in.NPMEmail)
	in.NPMTargetIP = strings.TrimSpace(in.NPMTargetIP)
	in.OIDCIssuer = strings.TrimSpace(in.OIDCIssuer)
	in.OIDCClientID = strings.TrimSpace(in.OIDCClientID)
	in.OIDCRedirectURL = strings.TrimSpace(in.OIDCRedirectURL)
	in.OIDCButtonLabel = strings.TrimSpace(in.OIDCButtonLabel)
	// Copy & paste often adds a trailing space or newline.
	trim(in.PiholePassword)
	trim(in.NPMPassword)
	trim(in.OIDCClientSecret)

	if code, field := s.validateSettings(&in); code != "" {
		writeError(w, http.StatusBadRequest, code, field)
		return
	}
	allowed, _ := parseDomainList(in.AllowedDomains)

	// Pi-hole and NPM must be reachable with the submitted values before
	// anything is stored (a working configuration cannot be saved broken).
	checks, err := s.checkBackends(r.Context(), &in)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if len(checks) > 0 {
		failed := []string{}
		for b, c := range checks {
			failed = append(failed, b+": "+c.Code)
		}
		s.audit(r, a.user, "settings_update", "", false, "connection check failed: "+strings.Join(failed, ", "))
		writeJSON(w, http.StatusUnprocessableEntity, settingsCheckError{Error: "settings_check_failed", Checks: checks})
		return
	}

	oidcEnabled := "false"
	if in.OIDCEnabled && !s.desktop() {
		oidcEnabled = "true"
	}
	plain := map[string]string{
		kPiholeURL:       in.PiholeURL,
		kPiholeCA:        strings.TrimSpace(in.PiholeCA),
		kNPMURL:          in.NPMURL,
		kNPMEmail:        in.NPMEmail,
		kNPMCA:           strings.TrimSpace(in.NPMCA),
		kNPMTargetIP:     in.NPMTargetIP,
		kAllowedDomains:  strings.Join(allowed, ","),
		kOIDCEnabled:     oidcEnabled,
		kOIDCIssuer:      in.OIDCIssuer,
		kOIDCClientID:    in.OIDCClientID,
		kOIDCRedirectURL: in.OIDCRedirectURL,
		kOIDCButtonLabel: in.OIDCButtonLabel,
		kVerified:        "true",
	}
	secrets := map[string]*string{
		kPiholePassword:   in.PiholePassword,
		kNPMPassword:      in.NPMPassword,
		kOIDCClientSecret: in.OIDCClientSecret,
	}
	if err := s.store.SaveSettings(plain, secrets); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.oidc.reset()

	changedSecrets := []string{}
	for k, v := range secrets {
		if v != nil {
			changedSecrets = append(changedSecrets, k)
		}
	}
	s.audit(r, a.user, "settings_update", "", true, "secrets changed: "+strings.Join(changedSecrets, ", "))
	configured, _ := s.backendsConfigured()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "configured": configured})
}

// backendCheck describes why the connection check of one backend failed.
type backendCheck struct {
	Code   string   `json:"code"`
	Detail string   `json:"detail,omitempty"`
	Fields []string `json:"fields"` // form fields to highlight
}

type settingsCheckError struct {
	Error  string                   `json:"error"`
	Checks map[string]*backendCheck `json:"checks"`
}

// checkBackends tests Pi-hole and NPM with the submitted settings (stored
// secrets are used where the form left a secret unchanged). It returns the
// failed checks keyed by backend; an empty map means both succeeded.
func (s *Server) checkBackends(ctx context.Context, in *settingsUpdate) (map[string]*backendCheck, error) {
	secret := func(p *string, key string) (string, error) {
		if p != nil {
			return *p, nil
		}
		return s.store.Secret(key)
	}
	piholePW, err := secret(in.PiholePassword, kPiholePassword)
	if err != nil {
		return nil, err
	}
	npmPW, err := secret(in.NPMPassword, kNPMPassword)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, backendTimeout)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	result := map[string]*backendCheck{}
	fail := func(backend string, c *backendCheck) {
		if c.Fields == nil {
			c.Fields = []string{}
		}
		mu.Lock()
		result[backend] = c
		mu.Unlock()
	}

	if missing := missingFields(map[string]string{"piholeUrl": in.PiholeURL, "piholePassword": piholePW}); len(missing) > 0 {
		fail("pihole", &backendCheck{Code: "required_missing", Fields: missing})
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ph, err := newPiholeClient(in.PiholeURL, piholePW, in.PiholeCA)
			if err == nil {
				defer ph.Logout(context.Background())
				_, err = ph.ListHosts(ctx)
			}
			if err != nil {
				fail("pihole", backendFailure("pihole", err, "piholeUrl", "piholePassword", "piholeCaPem"))
			}
		}()
	}

	if missing := missingFields(map[string]string{"npmUrl": in.NPMURL, "npmEmail": in.NPMEmail, "npmPassword": npmPW, "npmTargetIp": in.NPMTargetIP}); len(missing) > 0 {
		fail("npm", &backendCheck{Code: "required_missing", Fields: missing})
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nc, err := newNPMClient(in.NPMURL, in.NPMEmail, npmPW, in.NPMCA)
			if err == nil {
				_, err = nc.ListProxyHosts(ctx)
			}
			if err != nil {
				fail("npm", backendFailure("npm", err, "npmUrl", "npmPassword", "npmCaPem"))
			}
		}()
	}
	wg.Wait()
	return result, nil
}

// missingFields returns the names of empty values in stable order.
func missingFields(m map[string]string) []string {
	order := []string{"piholeUrl", "piholePassword", "npmUrl", "npmEmail", "npmPassword", "npmTargetIp"}
	out := []string{}
	for _, k := range order {
		if v, ok := m[k]; ok && strings.TrimSpace(v) == "" {
			out = append(out, k)
		}
	}
	return out
}

// backendFailure maps a backend error to an error code (same codes as the
// test endpoint) and the form fields most likely responsible.
func backendFailure(backend string, err error, urlField, pwField, caField string) *backendCheck {
	switch {
	case errors.Is(err, pihole.ErrAuth), errors.Is(err, npm.ErrAuth):
		f := []string{pwField}
		if backend == "npm" {
			f = []string{"npmEmail", pwField}
		}
		return &backendCheck{Code: backend + "_auth_failed", Detail: err.Error(), Fields: f}
	case errors.Is(err, npm.Err2FA):
		return &backendCheck{Code: "npm_2fa_enabled", Fields: []string{"npmEmail"}}
	case errors.Is(err, httpx.ErrNotHTTPS):
		return &backendCheck{Code: "https_required", Fields: []string{urlField}}
	}
	fields := []string{urlField}
	if strings.Contains(strings.ToLower(err.Error()), "certificate") {
		fields = append(fields, caField)
	}
	return &backendCheck{Code: backend + "_error", Detail: err.Error(), Fields: fields}
}

// validateSettings returns an error code and the offending field.
func (s *Server) validateSettings(in *settingsUpdate) (string, string) {
	for _, f := range []struct{ name, val string }{{"piholeUrl", in.PiholeURL}, {"npmUrl", in.NPMURL}} {
		if f.val == "" {
			continue
		}
		if _, err := httpx.NormalizeBaseURL(f.val); err != nil {
			if errors.Is(err, httpx.ErrNotHTTPS) {
				return "https_required", f.name
			}
			return "invalid_url", f.name
		}
	}
	for _, f := range []struct{ name, val string }{{"piholeCaPem", in.PiholeCA}, {"npmCaPem", in.NPMCA}} {
		if err := httpx.ValidateCAPEM(f.val); err != nil {
			return "invalid_ca_pem", f.name
		}
	}
	if in.NPMTargetIP != "" && net.ParseIP(in.NPMTargetIP) == nil {
		return "invalid_ip", "npmTargetIp"
	}
	if in.NPMEmail != "" && validateEmail(in.NPMEmail) != "" {
		return "invalid_email", "npmEmail"
	}
	if _, code := parseDomainList(in.AllowedDomains); code != "" {
		return code, "allowedDomains"
	}
	for _, p := range []*string{in.PiholePassword, in.NPMPassword, in.OIDCClientSecret} {
		if p != nil && (len(*p) > 1024 || containsControl(*p)) {
			return "invalid_secret", ""
		}
	}
	if len(in.OIDCButtonLabel) > 64 || containsControl(in.OIDCButtonLabel) {
		return "invalid_label", "oidcButtonLabel"
	}
	if in.OIDCEnabled && !s.desktop() {
		if in.OIDCIssuer == "" || in.OIDCClientID == "" || in.OIDCRedirectURL == "" {
			return "oidc_incomplete", ""
		}
		for _, f := range []struct{ name, val string }{{"oidcIssuer", in.OIDCIssuer}, {"oidcRedirectUrl", in.OIDCRedirectURL}} {
			u, err := url.Parse(f.val)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
				return "invalid_url", f.name
			}
		}
		if !strings.HasSuffix(strings.TrimRight(in.OIDCRedirectURL, "/"), "/api/auth/oidc/callback") {
			return "invalid_redirect_url", "oidcRedirectUrl"
		}
	}
	return "", ""
}

// handleTestSettings tests the stored connection to pihole, npm or oidc.
func (s *Server) handleTestSettings(w http.ResponseWriter, r *http.Request, a *authCtx) {
	st, err := s.loadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendTimeout)
	defer cancel()

	target := r.PathValue("target")
	var result map[string]any
	switch target {
	case "pihole":
		ph, err := s.piholeClient(st)
		if err != nil {
			writeBackendError(w, "pihole", err)
			return
		}
		defer ph.Logout(context.Background())
		hosts, err := ph.ListHosts(ctx)
		if err != nil {
			writeBackendError(w, "pihole", err)
			return
		}
		result = map[string]any{"ok": true, "count": len(hosts)}
	case "npm":
		nc, err := s.npmClient(st)
		if err != nil {
			writeBackendError(w, "npm", err)
			return
		}
		hosts, err := nc.ListProxyHosts(ctx)
		if err != nil {
			writeBackendError(w, "npm", err)
			return
		}
		result = map[string]any{"ok": true, "count": len(hosts)}
	case "oidc":
		if s.desktop() {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		if _, err := s.oidc.client(ctx, s, st); err != nil {
			writeError(w, http.StatusBadGateway, "oidc_error", err.Error())
			return
		}
		result = map[string]any{"ok": true}
	default:
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	s.audit(r, a.user, "settings_test", target, true, "")
	writeJSON(w, http.StatusOK, result)
}

// writeBackendError maps backend errors to stable error codes.
func writeBackendError(w http.ResponseWriter, backend string, err error) {
	switch {
	case errors.Is(err, errNotConfigured):
		writeError(w, http.StatusConflict, backend+"_not_configured")
	case errors.Is(err, pihole.ErrAuth), errors.Is(err, npm.ErrAuth):
		writeError(w, http.StatusBadGateway, backend+"_auth_failed", err.Error())
	case errors.Is(err, npm.Err2FA):
		writeError(w, http.StatusBadGateway, "npm_2fa_enabled")
	case errors.Is(err, httpx.ErrNotHTTPS):
		writeError(w, http.StatusBadGateway, "https_required")
	default:
		writeError(w, http.StatusBadGateway, backend+"_error", err.Error())
	}
}
