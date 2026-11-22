// Package httpx builds hardened HTTP clients for the backend APIs.
package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxResponseBody limits how much data is read from a backend response.
const MaxResponseBody = 10 << 20

// ErrNotHTTPS is returned for base URLs that do not use https.
var ErrNotHTTPS = errors.New("only https:// URLs are allowed")

// NewClient returns an HTTP client that
//   - always verifies TLS certificates (system roots plus optional PEM CA),
//   - requires TLS 1.2+,
//   - never follows redirects (credentials cannot leak to another host),
//   - ignores proxy environment variables (LAN traffic only).
func NewClient(caPEM string, timeout time.Duration) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(caPEM) != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("CA certificate: no valid PEM certificate found")
		}
		tlsCfg.RootCAs = pool
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// ValidateCAPEM checks that a PEM string contains at least one certificate.
func ValidateCAPEM(caPEM string) error {
	if strings.TrimSpace(caPEM) == "" {
		return nil
	}
	if !x509.NewCertPool().AppendCertsFromPEM([]byte(caPEM)) {
		return errors.New("no valid PEM certificate found")
	}
	return nil
}

// NormalizeBaseURL validates an https base URL and strips trailing slashes
// and the given suffixes (e.g. "/admin", "/api").
func NormalizeBaseURL(raw string, stripSuffixes ...string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid URL %q", raw)
	}
	if u.Scheme != "https" {
		return "", ErrNotHTTPS
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("URL must not contain credentials, query or fragment")
	}
	p := strings.TrimRight(u.Path, "/")
	for _, s := range stripSuffixes {
		p = strings.TrimSuffix(p, s)
	}
	u.Path = strings.TrimRight(p, "/")
	u.RawPath = ""
	return u.String(), nil
}

// ReadBody reads a response body with a size limit.
func ReadBody(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxResponseBody {
		return nil, errors.New("response too large")
	}
	return data, nil
}
