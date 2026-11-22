package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxydns/internal/npm"
	"proxydns/internal/pihole"
)

// ---- listing ---------------------------------------------------------------

type proxyDTO struct {
	ID            int    `json:"id"`
	ForwardScheme string `json:"forwardScheme"`
	ForwardHost   string `json:"forwardHost"`
	ForwardPort   int    `json:"forwardPort"`
	Certificate   string `json:"certificate"`
	AccessList    string `json:"accessList"`
	SSLForced     bool   `json:"sslForced"`
	HTTP2         bool   `json:"http2"`
	HSTS          bool   `json:"hsts"`
	Websocket     bool   `json:"websocket"`
	BlockExploits bool   `json:"blockExploits"`
	Caching       bool   `json:"caching"`
	Enabled       bool   `json:"enabled"`
}

type entryDTO struct {
	Domain      string    `json:"domain"`
	DNSIPs      []string  `json:"dnsIps"`
	PointsToNPM bool      `json:"pointsToNpm"`
	Proxy       *proxyDTO `json:"proxy,omitempty"`
}

func (s *Server) handleListEntries(w http.ResponseWriter, r *http.Request, a *authCtx) {
	st, err := s.loadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendTimeout)
	defer cancel()

	var (
		wg        sync.WaitGroup
		hosts     []pihole.HostEntry
		proxies   []npm.ProxyHost
		piholeErr error
		npmErr    error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		ph, err := s.piholeClient(st)
		if err != nil {
			piholeErr = err
			return
		}
		defer ph.Logout(context.Background())
		hosts, piholeErr = ph.ListHosts(ctx)
	}()
	go func() {
		defer wg.Done()
		nc, err := s.npmClient(st)
		if err != nil {
			npmErr = err
			return
		}
		proxies, npmErr = nc.ListProxyHosts(ctx)
	}()
	wg.Wait()

	byDomain := map[string]*entryDTO{}
	get := func(d string) *entryDTO {
		d = strings.ToLower(d)
		e, ok := byDomain[d]
		if !ok {
			e = &entryDTO{Domain: d, DNSIPs: []string{}}
			byDomain[d] = e
		}
		return e
	}
	for _, h := range hosts {
		for _, name := range h.Hostnames {
			e := get(name)
			e.DNSIPs = append(e.DNSIPs, h.IP)
			if h.IP == st.NPMTargetIP {
				e.PointsToNPM = true
			}
		}
	}
	for _, p := range proxies {
		dto := &proxyDTO{
			ID:            int(p.ID),
			ForwardScheme: p.ForwardScheme,
			ForwardHost:   p.ForwardHost,
			ForwardPort:   int(p.ForwardPort),
			SSLForced:     bool(p.SSLForced),
			HTTP2:         bool(p.HTTP2Support),
			HSTS:          bool(p.HSTSEnabled),
			Websocket:     bool(p.AllowWebsocketUpgrade),
			BlockExploits: bool(p.BlockExploits),
			Caching:       bool(p.CachingEnabled),
			Enabled:       bool(p.Enabled),
		}
		if p.Certificate != nil && p.CertificateID > 0 {
			dto.Certificate = certName(*p.Certificate)
		}
		if p.AccessList != nil && p.AccessListID > 0 {
			dto.AccessList = p.AccessList.Name
		}
		for _, d := range p.DomainNames {
			get(d).Proxy = dto
		}
	}
	entries := make([]*entryDTO, 0, len(byDomain))
	for _, e := range byDomain {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Domain < entries[j].Domain })

	resp := map[string]any{"entries": entries, "targetIp": st.NPMTargetIP}
	errs := map[string]map[string]string{}
	if piholeErr != nil {
		errs["pihole"] = backendErrorInfo("pihole", piholeErr)
	}
	if npmErr != nil {
		errs["npm"] = backendErrorInfo("npm", npmErr)
	}
	if len(errs) > 0 {
		resp["errors"] = errs
	}
	writeJSON(w, http.StatusOK, resp)
}

func backendErrorInfo(backend string, err error) map[string]string {
	switch {
	case errors.Is(err, errNotConfigured):
		return map[string]string{"code": backend + "_not_configured"}
	case errors.Is(err, pihole.ErrAuth), errors.Is(err, npm.ErrAuth):
		return map[string]string{"code": backend + "_auth_failed", "detail": err.Error()}
	case errors.Is(err, npm.Err2FA):
		return map[string]string{"code": "npm_2fa_enabled"}
	default:
		return map[string]string{"code": backend + "_error", "detail": err.Error()}
	}
}

func certName(c npm.Certificate) string {
	if c.NiceName != "" {
		return c.NiceName
	}
	return strings.Join(c.DomainNames, ", ")
}

// ---- options for the creation form ----------------------------------------

type optionDTO struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Expires string `json:"expires,omitempty"`
}

func (s *Server) handleEntryOptions(w http.ResponseWriter, r *http.Request, a *authCtx) {
	st, err := s.loadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendTimeout)
	defer cancel()
	nc, err := s.npmClient(st)
	if err != nil {
		writeBackendError(w, "npm", err)
		return
	}
	certs, err := nc.ListCertificates(ctx)
	if err != nil {
		writeBackendError(w, "npm", err)
		return
	}
	lists, err := nc.ListAccessLists(ctx)
	if err != nil {
		writeBackendError(w, "npm", err)
		return
	}
	certOpts := make([]optionDTO, 0, len(certs))
	for _, c := range certs {
		certOpts = append(certOpts, optionDTO{ID: int(c.ID), Name: certName(c), Expires: c.ExpiresOn})
	}
	listOpts := make([]optionDTO, 0, len(lists))
	for _, l := range lists {
		listOpts = append(listOpts, optionDTO{ID: int(l.ID), Name: l.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"certificates":   certOpts,
		"accessLists":    listOpts,
		"targetIp":       st.NPMTargetIP,
		"allowedDomains": st.AllowedDomains,
		"canAdvanced":    a.user.IsAdmin(),
	})
}

// ---- creation ---------------------------------------------------------------

type locationInput struct {
	Path           string `json:"path"`
	ForwardScheme  string `json:"forwardScheme"`
	ForwardHost    string `json:"forwardHost"`
	ForwardPort    int    `json:"forwardPort"`
	AdvancedConfig string `json:"advancedConfig"`
}

type entryInput struct {
	Domain         string          `json:"domain"`
	ForwardScheme  string          `json:"forwardScheme"`
	ForwardHost    string          `json:"forwardHost"`
	ForwardPort    int             `json:"forwardPort"`
	CertificateID  int             `json:"certificateId"`
	SSLForced      bool            `json:"sslForced"`
	HTTP2Support   bool            `json:"http2Support"`
	HSTSEnabled    bool            `json:"hstsEnabled"`
	HSTSSubdomains bool            `json:"hstsSubdomains"`
	BlockExploits  bool            `json:"blockExploits"`
	CachingEnabled bool            `json:"cachingEnabled"`
	Websocket      bool            `json:"websocket"`
	AccessListID   int             `json:"accessListId"`
	AdvancedConfig string          `json:"advancedConfig"`
	Locations      []locationInput `json:"locations"`
}

// validateEntry normalises and validates the input. It returns an error code
// and the offending field.
func validateEntry(in *entryInput, isAdmin bool, allowed []string) (string, string) {
	d, ok := normalizeDomain(in.Domain)
	if !ok {
		return "invalid_domain", "domain"
	}
	in.Domain = d
	if !domainAllowed(d, allowed) {
		return "domain_not_allowed", "domain"
	}
	if in.ForwardScheme != "http" && in.ForwardScheme != "https" {
		return "invalid_scheme", "forwardScheme"
	}
	in.ForwardHost = strings.TrimSpace(in.ForwardHost)
	if !validHost(in.ForwardHost) {
		return "invalid_host", "forwardHost"
	}
	if in.ForwardPort < 1 || in.ForwardPort > 65535 {
		return "invalid_port", "forwardPort"
	}
	if in.CertificateID < 0 || in.AccessListID < 0 {
		return "invalid_option", ""
	}
	if in.CertificateID == 0 {
		// Without certificate these options are meaningless and NPM would
		// produce a broken config.
		in.SSLForced, in.HTTP2Support, in.HSTSEnabled, in.HSTSSubdomains = false, false, false, false
	}
	if !in.HSTSEnabled {
		in.HSTSSubdomains = false
	}
	if in.AdvancedConfig != "" {
		if !isAdmin {
			return "advanced_admin_only", "advancedConfig"
		}
		if len(in.AdvancedConfig) > maxAdvancedLen || containsControl(in.AdvancedConfig) {
			return "invalid_advanced", "advancedConfig"
		}
	}
	if len(in.Locations) > maxLocations {
		return "too_many_locations", "locations"
	}
	seen := map[string]bool{}
	for i := range in.Locations {
		l := &in.Locations[i]
		l.Path = strings.TrimSpace(l.Path)
		l.ForwardHost = strings.TrimSpace(l.ForwardHost)
		if !pathRe.MatchString(l.Path) || len(l.Path) > 256 || seen[l.Path] {
			return "invalid_location_path", "locations"
		}
		seen[l.Path] = true
		if l.ForwardScheme != "http" && l.ForwardScheme != "https" {
			return "invalid_scheme", "locations"
		}
		if !validHost(l.ForwardHost) {
			return "invalid_host", "locations"
		}
		if l.ForwardPort < 1 || l.ForwardPort > 65535 {
			return "invalid_port", "locations"
		}
		if l.AdvancedConfig != "" {
			if !isAdmin {
				return "advanced_admin_only", "locations"
			}
			if len(l.AdvancedConfig) > maxAdvancedLen || containsControl(l.AdvancedConfig) {
				return "invalid_advanced", "locations"
			}
		}
	}
	return "", ""
}

func (in *entryInput) toNPM() npm.ProxyHostInput {
	locs := make([]npm.Location, 0, len(in.Locations))
	for _, l := range in.Locations {
		locs = append(locs, npm.Location{
			Path:           l.Path,
			ForwardScheme:  l.ForwardScheme,
			ForwardHost:    l.ForwardHost,
			ForwardPort:    l.ForwardPort,
			AdvancedConfig: l.AdvancedConfig,
		})
	}
	return npm.ProxyHostInput{
		DomainNames:           []string{in.Domain},
		ForwardScheme:         in.ForwardScheme,
		ForwardHost:           in.ForwardHost,
		ForwardPort:           in.ForwardPort,
		CertificateID:         in.CertificateID,
		SSLForced:             in.SSLForced,
		HSTSEnabled:           in.HSTSEnabled,
		HSTSSubdomains:        in.HSTSSubdomains,
		HTTP2Support:          in.HTTP2Support,
		BlockExploits:         in.BlockExploits,
		CachingEnabled:        in.CachingEnabled,
		AllowWebsocketUpgrade: in.Websocket,
		AccessListID:          in.AccessListID,
		AdvancedConfig:        in.AdvancedConfig,
		Locations:             locs,
		Meta:                  map[string]any{"letsencrypt_agree": false, "dns_challenge": false},
	}
}

// auditDetails summarises the options without any sensitive values.
func (in *entryInput) auditDetails(ip string) string {
	d := map[string]any{
		"dns":         ip,
		"forward":     in.ForwardScheme + "://" + in.ForwardHost + ":" + strconv.Itoa(in.ForwardPort),
		"certificate": in.CertificateID,
		"accessList":  in.AccessListID,
		"sslForced":   in.SSLForced,
		"http2":       in.HTTP2Support,
		"hsts":        in.HSTSEnabled,
		"websocket":   in.Websocket,
		"blockExpl":   in.BlockExploits,
		"caching":     in.CachingEnabled,
		"locations":   len(in.Locations),
		"advanced":    in.AdvancedConfig != "",
	}
	b, _ := json.Marshal(d)
	return string(b)
}

func (s *Server) handleCreateEntry(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in entryInput
	if !decodeJSON(w, r, &in) {
		return
	}
	st, err := s.loadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if st.NPMTargetIP == "" {
		writeError(w, http.StatusConflict, "target_ip_not_configured")
		return
	}
	if code, field := validateEntry(&in, a.user.IsAdmin(), st.AllowedDomains); code != "" {
		writeError(w, http.StatusBadRequest, code, field)
		return
	}

	// Only one creation at a time: the duplicate check and the creation must
	// not interleave with another request.
	s.entryMu.Lock()
	defer s.entryMu.Unlock()

	// Not bound to the request context: a client disconnect must not leave
	// a half-created entry without rollback.
	ctx, cancel := context.WithTimeout(context.Background(), 2*backendTimeout)
	defer cancel()

	ph, err := s.piholeClient(st)
	if err != nil {
		writeBackendError(w, "pihole", err)
		return
	}
	nc, err := s.npmClient(st)
	if err != nil {
		writeBackendError(w, "npm", err)
		return
	}
	// Log in to both systems before changing anything.
	if err := ph.Login(ctx); err != nil {
		writeBackendError(w, "pihole", err)
		return
	}
	defer ph.Logout(context.Background())
	if err := nc.Login(ctx); err != nil {
		writeBackendError(w, "npm", err)
		return
	}

	hosts, err := ph.ListHosts(ctx)
	if err != nil {
		writeBackendError(w, "pihole", err)
		return
	}
	for _, h := range hosts {
		for _, name := range h.Hostnames {
			if strings.EqualFold(name, in.Domain) {
				writeError(w, http.StatusConflict, "dns_exists", h.IP)
				return
			}
		}
	}
	proxies, err := nc.ListProxyHosts(ctx)
	if err != nil {
		writeBackendError(w, "npm", err)
		return
	}
	for _, p := range proxies {
		for _, d := range p.DomainNames {
			if strings.EqualFold(d, in.Domain) {
				writeError(w, http.StatusConflict, "proxy_exists")
				return
			}
		}
	}

	details := in.auditDetails(st.NPMTargetIP)

	// Step 1: DNS record.
	if err := ph.AddHost(ctx, st.NPMTargetIP, in.Domain); err != nil {
		s.audit(r, a.user, "entry_create", in.Domain, false, "pihole: "+err.Error())
		writeBackendError(w, "pihole", err)
		return
	}

	// Step 2: proxy host; roll back step 1 on failure.
	created, err := nc.CreateProxyHost(ctx, in.toNPM())
	if err != nil {
		rbCtx, rbCancel := context.WithTimeout(context.Background(), backendTimeout)
		defer rbCancel()
		rbErr := ph.DeleteHost(rbCtx, st.NPMTargetIP, in.Domain)
		if rbErr != nil {
			s.audit(r, a.user, "entry_create", in.Domain, false, "npm: "+err.Error()+"; ROLLBACK FAILED: "+rbErr.Error())
			s.log.Error("rollback of DNS record failed", "domain", in.Domain, "err", rbErr)
			writeError(w, http.StatusBadGateway, "rollback_failed", err.Error()+" / "+rbErr.Error())
			return
		}
		s.audit(r, a.user, "entry_create", in.Domain, false, "npm: "+err.Error()+"; DNS record rolled back")
		writeBackendError(w, "npm", err)
		return
	}

	s.audit(r, a.user, "entry_create", in.Domain, true, details)
	writeJSON(w, http.StatusCreated, map[string]any{
		"domain":  in.Domain,
		"proxyId": int(created.ID),
		"dnsIp":   st.NPMTargetIP,
		"created": time.Now().Unix(),
	})
}
