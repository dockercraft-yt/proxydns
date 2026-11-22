package server

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"proxydns/internal/config"
	"proxydns/internal/secure"
	"proxydns/internal/store"
)

// ---- fake Pi-hole v6 + NPM backend (one TLS server, distinct paths) --------

type fakeBackend struct {
	mu            sync.Mutex
	hosts         []string // "ip host"
	proxies       []map[string]any
	failNPMCreate bool
	piholeLogins  int
	piholeLogouts int
	lastProxy     map[string]any
}

func (f *fakeBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.EscapedPath()
	switch {
	// --- Pi-hole ---
	case p == "/api/auth" && r.Method == http.MethodPost:
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		if in["password"] != "pihole-app-pw" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]any{"session": map[string]any{"valid": false}})
			return
		}
		f.piholeLogins++
		json.NewEncoder(w).Encode(map[string]any{"session": map[string]any{"valid": true, "sid": "SID123"}})
	case p == "/api/auth" && r.Method == http.MethodDelete:
		f.piholeLogouts++
		w.WriteHeader(204)
	case strings.HasPrefix(p, "/api/config/dns/hosts"):
		if r.Header.Get("X-FTL-SID") != "SID123" {
			w.WriteHeader(401)
			return
		}
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{"config": map[string]any{"dns": map[string]any{"hosts": f.hosts}}})
			return
		}
		entry, _ := url.PathUnescape(strings.TrimPrefix(p, "/api/config/dns/hosts/"))
		if r.Method == http.MethodPut {
			f.hosts = append(f.hosts, entry)
			w.WriteHeader(201)
			return
		}
		if r.Method == http.MethodDelete {
			for i, h := range f.hosts {
				if h == entry {
					f.hosts = append(f.hosts[:i], f.hosts[i+1:]...)
					w.WriteHeader(204)
					return
				}
			}
			w.WriteHeader(404)
		}
	// --- NPM ---
	case p == "/api/tokens":
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		if in["identity"] != "api@example.com" || in["secret"] != "npm-pw" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "Invalid password"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"token": "JWT", "expires": "2099-01-01"})
	case strings.HasPrefix(p, "/api/nginx/"):
		if r.Header.Get("Authorization") != "Bearer JWT" {
			w.WriteHeader(401)
			return
		}
		switch {
		case p == "/api/nginx/proxy-hosts" && r.Method == http.MethodGet:
			// emulate ?expand=certificate
			out := []map[string]any{}
			for _, ph := range f.proxies {
				cp := map[string]any{}
				for k, v := range ph {
					cp[k] = v
				}
				if strings.Contains(r.URL.RawQuery, "certificate") && cp["certificate_id"] == float64(3) {
					cp["certificate"] = map[string]any{"id": 3, "nice_name": "*.home.lan"}
				}
				out = append(out, cp)
			}
			json.NewEncoder(w).Encode(out)
		case p == "/api/nginx/proxy-hosts" && r.Method == http.MethodPost:
			if f.failNPMCreate {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "validation failed"}})
				return
			}
			var in map[string]any
			json.NewDecoder(r.Body).Decode(&in)
			in["id"] = len(f.proxies) + 1
			in["enabled"] = 1 // old NPM style integer boolean
			f.proxies = append(f.proxies, in)
			f.lastProxy = in
			json.NewEncoder(w).Encode(in)
		case p == "/api/nginx/certificates":
			json.NewEncoder(w).Encode([]map[string]any{{"id": 3, "nice_name": "*.home.lan", "provider": "letsencrypt", "domain_names": []string{"*.home.lan"}}})
		case p == "/api/nginx/access-lists":
			json.NewEncoder(w).Encode([]map[string]any{{"id": 1, "name": "LAN only"}})
		default:
			w.WriteHeader(404)
		}
	default:
		w.WriteHeader(404)
	}
}

// ---- test client --------------------------------------------------------------

type client struct {
	t    *testing.T
	base string
	hc   *http.Client
	csrf string
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, hc: &http.Client{Jar: jar}}
}

func (c *client) do(method, path string, body any, headers ...string) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-ProxyDNS-Request", "1")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i+1] == "" {
			req.Header.Del(headers[i])
		} else {
			req.Header.Set(headers[i], headers[i+1])
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &out)
	if out == nil {
		out = map[string]any{"_raw": string(data)}
	}
	if csrf, ok := out["csrf"].(string); ok && csrf != "" {
		c.csrf = csrf
	}
	return resp.StatusCode, out
}

func expect(t *testing.T, status int, out map[string]any, wantStatus int, wantErr string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status %d, want %d (%v)", status, wantStatus, out)
	}
	if wantErr != "" && out["error"] != wantErr {
		t.Fatalf("error %v, want %s (%v)", out["error"], wantErr, out)
	}
}

type env struct {
	srv     *Server
	ts      *httptest.Server
	backend *fakeBackend
	beURL   string
	caPEM   string
	store   *store.Store
}

func newEnv(t *testing.T) *env {
	t.Helper()
	key, _ := secure.RandomBytes(32)
	box, _ := secure.NewBox(key)
	st, err := store.Open(filepath.Join(t.TempDir(), "proxydns.db"), box, secure.DeriveSubkey(key, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	st.CheckMasterKey()
	cfg := &config.Config{Mode: config.ModeServer, SessionIdle: 30 * time.Minute, SessionMax: 12 * time.Hour}
	srv := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.SetSetupToken("SETUP-CODE")
	ts := httptest.NewServer(srv.Handler())

	fb := &fakeBackend{}
	be := httptest.NewTLSServer(fb)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: be.Certificate().Raw}))
	t.Cleanup(func() { ts.Close(); be.Close(); srv.Close(); st.Close() })
	return &env{srv: srv, ts: ts, backend: fb, beURL: be.URL, caPEM: caPEM, store: st}
}

func (e *env) adminClient(t *testing.T) *client {
	c := newClient(t, e.ts.URL)
	st, out := c.do("POST", "/api/setup", map[string]string{"token": "SETUP-CODE", "username": "admin", "password": "admin-password-123"})
	expect(t, st, out, 200, "")
	return c
}

func (e *env) configure(t *testing.T, c *client, extra map[string]any) {
	s := map[string]any{
		"piholeUrl": e.beURL, "piholePassword": "pihole-app-pw", "piholeCaPem": e.caPEM,
		"npmUrl": e.beURL, "npmEmail": "api@example.com", "npmPassword": "npm-pw", "npmCaPem": e.caPEM,
		"npmTargetIp": "192.168.1.5", "allowedDomains": "home.lan",
	}
	for k, v := range extra {
		s[k] = v
	}
	st, out := c.do("PUT", "/api/settings", s)
	expect(t, st, out, 200, "")
}

func validEntry() map[string]any {
	return map[string]any{
		"domain": "App.Home.Lan", "forwardScheme": "http", "forwardHost": "192.168.1.20", "forwardPort": 8080,
		"certificateId": 3, "sslForced": true, "http2Support": true, "websocket": true, "blockExploits": true,
	}
}

// ---- tests ----------------------------------------------------------------------

func TestSetupRequiresTokenAndHeader(t *testing.T) {
	e := newEnv(t)
	c := newClient(t, e.ts.URL)

	st, out := c.do("GET", "/api/info", nil)
	expect(t, st, out, 200, "")
	if out["setupRequired"] != true || out["setupNeedsCode"] != true {
		t.Fatalf("info: %v", out)
	}
	body := map[string]string{"token": "SETUP-CODE", "username": "admin", "password": "admin-password-123"}
	st, out = c.do("POST", "/api/setup", body, "X-ProxyDNS-Request", "")
	expect(t, st, out, 403, "csrf")
	st, out = c.do("POST", "/api/setup", map[string]string{"token": "wrong", "username": "admin", "password": "admin-password-123"})
	expect(t, st, out, 401, "invalid_setup_token")
	st, out = c.do("POST", "/api/setup", map[string]string{"token": "SETUP-CODE", "username": "admin", "password": "short"})
	expect(t, st, out, 400, "password_too_short")
	st, out = c.do("POST", "/api/setup", body)
	expect(t, st, out, 200, "")
	// second setup impossible
	st, out = newClient(t, e.ts.URL).do("POST", "/api/setup", body)
	expect(t, st, out, 409, "setup_done")
}

func TestAuthAndCSRF(t *testing.T) {
	e := newEnv(t)
	c := e.adminClient(t)
	st, out := c.do("GET", "/api/auth/me", nil)
	expect(t, st, out, 200, "")

	// state-changing request without session CSRF token
	csrf := c.csrf
	c.csrf = ""
	st, out = c.do("PUT", "/api/settings", map[string]any{})
	expect(t, st, out, 403, "csrf")
	c.csrf = csrf

	anon := newClient(t, e.ts.URL)
	st, out = anon.do("GET", "/api/entries", nil)
	expect(t, st, out, 401, "unauthorized")

	// wrong passwords lock the account
	for i := 0; i < 5; i++ {
		st, out = anon.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "wrong-password-x"})
		expect(t, st, out, 401, "invalid_credentials")
	}
	st, out = anon.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "admin-password-123"})
	expect(t, st, out, 401, "account_locked")
}

func TestSettingsRequireHTTPS(t *testing.T) {
	e := newEnv(t)
	c := e.adminClient(t)
	st, out := c.do("PUT", "/api/settings", map[string]any{"piholeUrl": "http://pi.hole"})
	expect(t, st, out, 400, "https_required")
	st, out = c.do("PUT", "/api/settings", map[string]any{"npmCaPem": "garbage"})
	expect(t, st, out, 400, "invalid_ca_pem")

	e.configure(t, c, nil)
	st, out = c.do("GET", "/api/settings", nil)
	expect(t, st, out, 200, "")
	if out["piholePasswordSet"] != true || out["npmPasswordSet"] != true {
		t.Fatalf("secrets not flagged: %v", out)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "pihole-app-pw") || strings.Contains(string(raw), "npm-pw") {
		t.Fatal("secret leaked in settings response")
	}
	st, out = c.do("POST", "/api/settings/test/pihole", nil)
	expect(t, st, out, 200, "")
	st, out = c.do("POST", "/api/settings/test/npm", nil)
	expect(t, st, out, 200, "")
}

func TestSetupModeUntilBackendsConfigured(t *testing.T) {
	e := newEnv(t)
	c := e.adminClient(t)
	st, out := c.do("GET", "/api/auth/me", nil)
	expect(t, st, out, 200, "")
	if out["configured"] == true {
		t.Fatal("fresh install must be in setup mode")
	}
	for _, p := range []string{"/api/entries", "/api/entries/options", "/api/users", "/api/audit"} {
		st, out = c.do("GET", p, nil)
		expect(t, st, out, 409, "setup_incomplete")
	}
	// only settings stay reachable, account changes are blocked too
	st, out = c.do("GET", "/api/settings", nil)
	expect(t, st, out, 200, "")
	st, out = c.do("POST", "/api/account/totp/setup", nil)
	expect(t, st, out, 409, "setup_incomplete")

	// incomplete configuration (NPM password missing) is rejected
	st, out = c.do("PUT", "/api/settings", map[string]any{
		"piholeUrl": e.beURL, "piholePassword": "pihole-app-pw", "piholeCaPem": e.caPEM,
		"npmUrl": e.beURL, "npmEmail": "api@example.com", "npmTargetIp": "192.168.1.5", "npmCaPem": e.caPEM,
	})
	expect(t, st, out, 422, "settings_check_failed")
	checks := out["checks"].(map[string]any)
	if _, ok := checks["pihole"]; ok {
		t.Fatalf("pihole should pass: %v", checks)
	}
	npmCheck := checks["npm"].(map[string]any)
	if npmCheck["code"] != "required_missing" || len(npmCheck["fields"].([]any)) != 1 || npmCheck["fields"].([]any)[0] != "npmPassword" {
		t.Fatalf("unexpected npm check: %v", npmCheck)
	}

	// wrong credentials are rejected and nothing is stored
	st, out = c.do("PUT", "/api/settings", map[string]any{
		"piholeUrl": e.beURL, "piholePassword": "wrong", "piholeCaPem": e.caPEM,
		"npmUrl": e.beURL, "npmEmail": "api@example.com", "npmPassword": "wrong", "npmTargetIp": "192.168.1.5", "npmCaPem": e.caPEM,
	})
	expect(t, st, out, 422, "settings_check_failed")
	checks = out["checks"].(map[string]any)
	if checks["pihole"].(map[string]any)["code"] != "pihole_auth_failed" || checks["npm"].(map[string]any)["code"] != "npm_auth_failed" {
		t.Fatalf("unexpected checks: %v", checks)
	}
	st, out = c.do("GET", "/api/settings", nil)
	expect(t, st, out, 200, "")
	if out["piholeUrl"] != "" || out["piholePasswordSet"] != false {
		t.Fatalf("failed check must not store settings: %v", out)
	}
	st, out = c.do("GET", "/api/users", nil)
	expect(t, st, out, 409, "setup_incomplete")

	e.configure(t, c, nil)
	st, out = c.do("GET", "/api/auth/me", nil)
	expect(t, st, out, 200, "")
	if out["configured"] != true {
		t.Fatalf("expected configured=true: %v", out)
	}
	st, out = c.do("GET", "/api/users", nil)
	expect(t, st, out, 200, "")

	// later changes are checked as well: a wrong password keeps the old config
	st, out = c.do("PUT", "/api/settings", map[string]any{
		"piholeUrl": e.beURL, "piholePassword": "wrong", "piholeCaPem": e.caPEM,
		"npmUrl": e.beURL, "npmEmail": "api@example.com", "npmTargetIp": "192.168.1.5", "npmCaPem": e.caPEM,
	})
	expect(t, st, out, 422, "settings_check_failed")
	st, out = c.do("POST", "/api/settings/test/pihole", nil)
	expect(t, st, out, 200, "")
}

func TestUntrustedCertificateRejected(t *testing.T) {
	e := newEnv(t)
	c := e.adminClient(t)
	st, out := c.do("PUT", "/api/settings", map[string]any{
		"piholeUrl": e.beURL, "piholePassword": "pihole-app-pw",
		"npmUrl": e.beURL, "npmEmail": "api@example.com", "npmPassword": "npm-pw", "npmCaPem": e.caPEM, "npmTargetIp": "192.168.1.5",
	})
	expect(t, st, out, 422, "settings_check_failed")
	ph := out["checks"].(map[string]any)["pihole"].(map[string]any)
	if ph["code"] != "pihole_error" || !strings.Contains(ph["detail"].(string), "certificate") {
		t.Fatalf("expected certificate error, got %v", ph)
	}
	if fields := ph["fields"].([]any); len(fields) != 2 || fields[1] != "piholeCaPem" {
		t.Fatalf("expected CA field to be highlighted: %v", fields)
	}
}

func TestCreateEntry(t *testing.T) {
	e := newEnv(t)
	c := e.adminClient(t)
	e.configure(t, c, nil)

	st, out := c.do("POST", "/api/entries", validEntry())
	expect(t, st, out, 201, "")
	if out["domain"] != "app.home.lan" {
		t.Fatalf("domain not normalised: %v", out)
	}
	e.backend.mu.Lock()
	if len(e.backend.hosts) != 1 || e.backend.hosts[0] != "192.168.1.5 app.home.lan" {
		t.Fatalf("pihole hosts: %v", e.backend.hosts)
	}
	if e.backend.lastProxy["forward_host"] != "192.168.1.20" || e.backend.lastProxy["certificate_id"] != float64(3) || e.backend.lastProxy["ssl_forced"] != true {
		t.Fatalf("npm payload: %v", e.backend.lastProxy)
	}
	if e.backend.piholeLogins != e.backend.piholeLogouts {
		t.Fatalf("pihole sessions leaked: %d logins, %d logouts", e.backend.piholeLogins, e.backend.piholeLogouts)
	}
	e.backend.mu.Unlock()

	st, out = c.do("POST", "/api/entries", validEntry())
	expect(t, st, out, 409, "dns_exists")

	st, out = c.do("GET", "/api/entries", nil)
	expect(t, st, out, 200, "")
	entries := out["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries: %v", out)
	}
	en := entries[0].(map[string]any)
	if en["pointsToNpm"] != true || en["proxy"].(map[string]any)["certificate"] != "*.home.lan" || en["proxy"].(map[string]any)["enabled"] != true {
		t.Fatalf("entry: %v", en)
	}

	st, out = c.do("GET", "/api/entries/options", nil)
	expect(t, st, out, 200, "")
	if len(out["certificates"].([]any)) != 1 || len(out["accessLists"].([]any)) != 1 {
		t.Fatalf("options: %v", out)
	}
}

// Regression: without allowed domains the list must be [] (not null),
// otherwise the "new entry" page crashed in the browser.
func TestEntryOptionsWithoutAllowedDomains(t *testing.T) {
	e := newEnv(t)
	c := e.adminClient(t)
	e.configure(t, c, map[string]any{"allowedDomains": ""})
	st, out := c.do("GET", "/api/entries/options", nil)
	expect(t, st, out, 200, "")
	if list, ok := out["allowedDomains"].([]any); !ok || len(list) != 0 {
		t.Fatalf("allowedDomains = %#v, want []", out["allowedDomains"])
	}
}

func TestCreateEntryRollsBackDNS(t *testing.T) {
	e := newEnv(t)
	c := e.adminClient(t)
	e.configure(t, c, nil)
	e.backend.failNPMCreate = true
	st, out := c.do("POST", "/api/entries", validEntry())
	expect(t, st, out, 502, "npm_error")
	e.backend.mu.Lock()
	defer e.backend.mu.Unlock()
	if len(e.backend.hosts) != 0 {
		t.Fatalf("DNS record not rolled back: %v", e.backend.hosts)
	}
}

func TestEntryValidation(t *testing.T) {
	e := newEnv(t)
	c := e.adminClient(t)
	e.configure(t, c, nil)

	cases := []struct {
		mod  func(m map[string]any)
		code string
	}{
		{func(m map[string]any) { m["domain"] = "google.com" }, "domain_not_allowed"},
		{func(m map[string]any) { m["domain"] = "*.home.lan" }, "invalid_domain"},
		{func(m map[string]any) { m["domain"] = "a b.home.lan" }, "invalid_domain"},
		{func(m map[string]any) { m["forwardHost"] = "1.2.3.4\nhost" }, "invalid_host"},
		{func(m map[string]any) { m["forwardPort"] = 70000 }, "invalid_port"},
		{func(m map[string]any) { m["forwardScheme"] = "ftp" }, "invalid_scheme"},
		{func(m map[string]any) {
			m["locations"] = []map[string]any{{"path": "/x; evil", "forwardScheme": "http", "forwardHost": "h", "forwardPort": 1}}
		}, "invalid_location_path"},
	}
	for _, tc := range cases {
		m := validEntry()
		tc.mod(m)
		st, out := c.do("POST", "/api/entries", m)
		expect(t, st, out, 400, tc.code)
	}

	// normal user may not set raw nginx config
	st, out := c.do("POST", "/api/users", map[string]string{"username": "bob", "password": "bob-password-123", "role": "user"})
	expect(t, st, out, 201, "")
	bob := newClient(t, e.ts.URL)
	st, out = bob.do("POST", "/api/auth/login", map[string]string{"username": "bob", "password": "bob-password-123"})
	expect(t, st, out, 200, "")
	m := validEntry()
	m["advancedConfig"] = "return 301 https://evil;"
	st, out = bob.do("POST", "/api/entries", m)
	expect(t, st, out, 400, "advanced_admin_only")
	st, out = bob.do("GET", "/api/settings", nil)
	expect(t, st, out, 403, "forbidden")
	st, out = bob.do("GET", "/api/audit", nil)
	expect(t, st, out, 403, "forbidden")
}

func TestTOTPFlow(t *testing.T) {
	e := newEnv(t)
	c := e.adminClient(t)
	e.configure(t, c, nil)
	st, out := c.do("POST", "/api/account/totp/setup", nil)
	expect(t, st, out, 200, "")
	secret := out["secret"].(string)
	if !strings.HasPrefix(out["qr"].(string), "data:image/png;base64,") {
		t.Fatal("no QR code")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	st, out = c.do("POST", "/api/account/totp/enable", map[string]string{"code": code})
	expect(t, st, out, 200, "")

	c2 := newClient(t, e.ts.URL)
	st, out = c2.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "admin-password-123"})
	expect(t, st, out, 200, "")
	if out["mfaRequired"] != true || out["user"] != nil {
		t.Fatalf("expected MFA step: %v", out)
	}
	// pending session must not grant access
	st, out = c2.do("GET", "/api/entries", nil)
	expect(t, st, out, 401, "mfa_required")
	// code already used during enrolment -> replay rejected
	st, out = c2.do("POST", "/api/auth/totp", map[string]string{"code": code})
	expect(t, st, out, 401, "invalid_code")
	next, _ := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	st, out = c2.do("POST", "/api/auth/totp", map[string]string{"code": next})
	expect(t, st, out, 200, "")
	st, out = c2.do("GET", "/api/auth/me", nil)
	expect(t, st, out, 200, "")
}

func TestAuditLogged(t *testing.T) {
	e := newEnv(t)
	c := e.adminClient(t)
	e.configure(t, c, nil)
	c.do("POST", "/api/entries", validEntry())
	st, out := c.do("GET", "/api/audit", nil)
	expect(t, st, out, 200, "")
	found := false
	for _, x := range out["entries"].([]any) {
		en := x.(map[string]any)
		if en["action"] == "entry_create" && en["success"] == true && en["target"] == "app.home.lan" {
			found = true
		}
	}
	if !found {
		t.Fatalf("entry_create not audited: %v", out)
	}
	st, out = c.do("GET", "/api/audit/verify", nil)
	expect(t, st, out, 200, "")
	if out["ok"] != true {
		t.Fatalf("audit verify: %v", out)
	}
}

func TestDesktopModeBearer(t *testing.T) {
	key, _ := secure.RandomBytes(32)
	box, _ := secure.NewBox(key)
	st, _ := store.Open(filepath.Join(t.TempDir(), "d.db"), box, key)
	defer st.Close()
	cfg := config.DesktopConfig()
	srv := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c := newClient(t, ts.URL)
	// desktop setup needs no code
	s, out := c.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "admin-password-123"})
	expect(t, s, out, 200, "")
	tok, _ := out["token"].(string)
	if tok == "" {
		t.Fatal("no bearer token in desktop mode")
	}
	// cookies are not used in desktop mode
	s, out = c.do("GET", "/api/auth/me", nil)
	expect(t, s, out, 401, "unauthorized")
	s, out = c.do("GET", "/api/auth/me", nil, "Authorization", "Bearer "+tok)
	expect(t, s, out, 200, "")
	// OIDC routes do not exist in desktop mode
	resp, _ := http.Get(ts.URL + "/api/auth/oidc/start")
	if resp.StatusCode != 404 {
		t.Fatalf("oidc start in desktop mode: %d", resp.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("headers: %v", resp.Header)
	}
}
