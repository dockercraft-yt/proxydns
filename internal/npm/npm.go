// Package npm is a minimal client for the Nginx Proxy Manager API.
package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"proxydns/internal/httpx"
)

var (
	// ErrAuth is returned when the credentials are rejected.
	ErrAuth = errors.New("npm: authentication failed")
	// Err2FA is returned when the NPM user has 2FA enabled, which API logins
	// cannot handle. Use a dedicated API user without 2FA.
	Err2FA = errors.New("npm: user has two-factor authentication enabled")
)

// APIError is an error reported by the NPM API.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("npm: HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("npm: HTTP %d", e.Status)
}

// Bool accepts true/false as well as 1/0 (older NPM versions use integers).
type Bool bool

// UnmarshalJSON implements json.Unmarshaler.
func (b *Bool) UnmarshalJSON(data []byte) error {
	switch strings.Trim(string(data), `"`) {
	case "true", "1":
		*b = true
	case "false", "0", "null", "":
		*b = false
	default:
		return fmt.Errorf("invalid boolean %s", data)
	}
	return nil
}

// Int accepts numbers and numeric strings.
type Int int

// UnmarshalJSON implements json.Unmarshaler.
func (i *Int) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "null" || s == "" {
		*i = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		// e.g. certificate_id "new" during creation; treat as none
		*i = 0
		return nil
	}
	*i = Int(n)
	return nil
}

// Certificate is an SSL certificate managed by NPM.
type Certificate struct {
	ID          Int      `json:"id"`
	NiceName    string   `json:"nice_name"`
	Provider    string   `json:"provider"`
	DomainNames []string `json:"domain_names"`
	ExpiresOn   string   `json:"expires_on"`
}

// AccessList is an NPM access list.
type AccessList struct {
	ID   Int    `json:"id"`
	Name string `json:"name"`
}

// ProxyHost is an existing proxy host.
type ProxyHost struct {
	ID                    Int          `json:"id"`
	DomainNames           []string     `json:"domain_names"`
	ForwardScheme         string       `json:"forward_scheme"`
	ForwardHost           string       `json:"forward_host"`
	ForwardPort           Int          `json:"forward_port"`
	CertificateID         Int          `json:"certificate_id"`
	AccessListID          Int          `json:"access_list_id"`
	SSLForced             Bool         `json:"ssl_forced"`
	HSTSEnabled           Bool         `json:"hsts_enabled"`
	HSTSSubdomains        Bool         `json:"hsts_subdomains"`
	HTTP2Support          Bool         `json:"http2_support"`
	BlockExploits         Bool         `json:"block_exploits"`
	CachingEnabled        Bool         `json:"caching_enabled"`
	AllowWebsocketUpgrade Bool         `json:"allow_websocket_upgrade"`
	Enabled               Bool         `json:"enabled"`
	Certificate           *Certificate `json:"certificate"`
	AccessList            *AccessList  `json:"access_list"`
}

// Location is a custom location of a proxy host.
type Location struct {
	Path           string `json:"path"`
	ForwardScheme  string `json:"forward_scheme"`
	ForwardHost    string `json:"forward_host"`
	ForwardPort    int    `json:"forward_port"`
	AdvancedConfig string `json:"advanced_config"`
}

// ProxyHostInput is the payload to create a proxy host.
type ProxyHostInput struct {
	DomainNames           []string       `json:"domain_names"`
	ForwardScheme         string         `json:"forward_scheme"`
	ForwardHost           string         `json:"forward_host"`
	ForwardPort           int            `json:"forward_port"`
	CertificateID         int            `json:"certificate_id"`
	SSLForced             bool           `json:"ssl_forced"`
	HSTSEnabled           bool           `json:"hsts_enabled"`
	HSTSSubdomains        bool           `json:"hsts_subdomains"`
	HTTP2Support          bool           `json:"http2_support"`
	BlockExploits         bool           `json:"block_exploits"`
	CachingEnabled        bool           `json:"caching_enabled"`
	AllowWebsocketUpgrade bool           `json:"allow_websocket_upgrade"`
	AccessListID          int            `json:"access_list_id"`
	AdvancedConfig        string         `json:"advanced_config"`
	Locations             []Location     `json:"locations"`
	Meta                  map[string]any `json:"meta"`
}

// Client talks to one NPM instance. It is not safe for concurrent use.
type Client struct {
	base     string
	email    string
	password string
	hc       *http.Client
	token    string
}

// New creates a client. baseURL must be https.
func New(baseURL, email, password string, hc *http.Client) (*Client, error) {
	base, err := httpx.NormalizeBaseURL(baseURL, "/api")
	if err != nil {
		return nil, err
	}
	return &Client{base: base, email: email, password: password, hc: hc}, nil
}

// Login obtains a bearer token.
func (c *Client) Login(ctx context.Context) error {
	var out struct {
		Token       string `json:"token"`
		Requires2FA bool   `json:"requires_2fa"`
	}
	err := c.do(ctx, http.MethodPost, "/api/tokens", map[string]string{"identity": c.email, "secret": c.password}, &out)
	var apiErr *APIError
	if errors.As(err, &apiErr) && (apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusBadRequest) {
		return ErrAuth
	}
	if err != nil {
		return err
	}
	if out.Requires2FA {
		return Err2FA
	}
	if out.Token == "" {
		return ErrAuth
	}
	c.token = out.Token
	return nil
}

// ListProxyHosts returns all proxy hosts including certificate and access list.
func (c *Client) ListProxyHosts(ctx context.Context) ([]ProxyHost, error) {
	var out []ProxyHost
	err := c.authedDo(ctx, http.MethodGet, "/api/nginx/proxy-hosts?expand=certificate,access_list", nil, &out)
	return out, err
}

// ListCertificates returns all certificates.
func (c *Client) ListCertificates(ctx context.Context) ([]Certificate, error) {
	var out []Certificate
	err := c.authedDo(ctx, http.MethodGet, "/api/nginx/certificates", nil, &out)
	return out, err
}

// ListAccessLists returns all access lists.
func (c *Client) ListAccessLists(ctx context.Context) ([]AccessList, error) {
	var out []AccessList
	err := c.authedDo(ctx, http.MethodGet, "/api/nginx/access-lists", nil, &out)
	return out, err
}

// CreateProxyHost creates a proxy host.
func (c *Client) CreateProxyHost(ctx context.Context, in ProxyHostInput) (*ProxyHost, error) {
	if in.Locations == nil {
		in.Locations = []Location{}
	}
	if in.Meta == nil {
		in.Meta = map[string]any{}
	}
	var out ProxyHost
	if err := c.authedDo(ctx, http.MethodPost, "/api/nginx/proxy-hosts", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) authedDo(ctx context.Context, method, path string, in, out any) error {
	if c.token == "" {
		if err := c.Login(ctx); err != nil {
			return err
		}
	}
	return c.do(ctx, method, path, in, out)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var req *http.Request
	var err error
	if in != nil {
		data, merr := json.Marshal(in)
		if merr != nil {
			return merr
		}
		req, err = http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(data))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, c.base+path, nil)
	}
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("npm: %w", err)
	}
	defer resp.Body.Close()
	data, err := httpx.ReadBody(resp.Body)
	if err != nil {
		return fmt.Errorf("npm: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return &APIError{Status: resp.StatusCode, Message: e.Error.Message}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("npm: invalid response: %w", err)
		}
	}
	return nil
}
