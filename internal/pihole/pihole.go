// Package pihole is a minimal client for the Pi-hole v6 REST API, limited to
// local DNS records (dns.hosts).
package pihole

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"proxydns/internal/httpx"
)

// ErrAuth is returned when the password / app password is rejected.
var ErrAuth = errors.New("pihole: authentication failed")

// APIError is an error reported by the Pi-hole API.
type APIError struct {
	Status  int
	Key     string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("pihole: HTTP %d: %s (%s)", e.Status, e.Message, e.Key)
	}
	return fmt.Sprintf("pihole: HTTP %d", e.Status)
}

// HostEntry is one local DNS record line ("IP host [host...]").
type HostEntry struct {
	IP        string
	Hostnames []string
}

// Client talks to one Pi-hole instance. It is not safe for concurrent use.
type Client struct {
	base     string
	password string
	hc       *http.Client
	sid      string
	authed   bool
}

// New creates a client. baseURL must be https (e.g. https://pi.hole).
func New(baseURL, password string, hc *http.Client) (*Client, error) {
	base, err := httpx.NormalizeBaseURL(baseURL, "/admin", "/api")
	if err != nil {
		return nil, err
	}
	return &Client{base: base, password: password, hc: hc}, nil
}

// Login creates an API session. An app password is recommended.
func (c *Client) Login(ctx context.Context) error {
	var out struct {
		Session struct {
			Valid   bool    `json:"valid"`
			SID     *string `json:"sid"`
			Message string  `json:"message"`
		} `json:"session"`
	}
	err := c.do(ctx, http.MethodPost, "/api/auth", map[string]string{"password": c.password}, &out)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
		return fmt.Errorf("%w (HTTP 401: %s)", ErrAuth, apiErr.Message)
	}
	if err != nil {
		return err
	}
	if !out.Session.Valid {
		return fmt.Errorf("%w (%s)", ErrAuth, out.Session.Message)
	}
	if out.Session.SID != nil {
		c.sid = *out.Session.SID
	}
	c.authed = true
	return nil
}

// Logout ends the API session. Pi-hole limits concurrent sessions, so every
// Login should be paired with a Logout.
func (c *Client) Logout(ctx context.Context) {
	if c.sid != "" {
		_ = c.do(ctx, http.MethodDelete, "/api/auth", nil, nil)
	}
	c.sid = ""
	c.authed = false
}

// ListHosts returns all local DNS records.
func (c *Client) ListHosts(ctx context.Context) ([]HostEntry, error) {
	var out struct {
		Config struct {
			DNS struct {
				Hosts []string `json:"hosts"`
			} `json:"dns"`
		} `json:"config"`
	}
	if err := c.authedDo(ctx, http.MethodGet, "/api/config/dns/hosts", nil, &out); err != nil {
		return nil, err
	}
	entries := make([]HostEntry, 0, len(out.Config.DNS.Hosts))
	for _, line := range out.Config.DNS.Hosts {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		entries = append(entries, HostEntry{IP: f[0], Hostnames: f[1:]})
	}
	return entries, nil
}

// AddHost creates a local DNS record "ip domain".
func (c *Client) AddHost(ctx context.Context, ip, domain string) error {
	return c.authedDo(ctx, http.MethodPut, hostPath(ip, domain), nil, nil)
}

// DeleteHost removes a local DNS record "ip domain".
func (c *Client) DeleteHost(ctx context.Context, ip, domain string) error {
	return c.authedDo(ctx, http.MethodDelete, hostPath(ip, domain), nil, nil)
}

func hostPath(ip, domain string) string {
	return "/api/config/dns/hosts/" + url.PathEscape(ip+" "+domain)
}

func (c *Client) authedDo(ctx context.Context, method, path string, in, out any) error {
	if !c.authed {
		if err := c.Login(ctx); err != nil {
			return err
		}
	}
	return c.do(ctx, method, path, in, out)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body *bytes.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, c.base+path, body)
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
	if c.sid != "" {
		req.Header.Set("X-FTL-SID", c.sid)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("pihole: %w", err)
	}
	defer resp.Body.Close()
	data, err := httpx.ReadBody(resp.Body)
	if err != nil {
		return fmt.Errorf("pihole: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Key     string `json:"key"`
				Message string `json:"message"`
			} `json:"error"`
			// A failed login (401) reports its reason in session.message instead.
			Session struct {
				Message string `json:"message"`
			} `json:"session"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Error.Message
		if msg == "" {
			msg = e.Session.Message
		}
		return &APIError{Status: resp.StatusCode, Key: e.Error.Key, Message: msg}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("pihole: invalid response: %w", err)
		}
	}
	return nil
}
