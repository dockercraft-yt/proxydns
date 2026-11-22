package server

import (
	"net"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	minPasswordLen = 12
	maxPasswordLen = 256
	maxAdvancedLen = 16 * 1024
	maxLocations   = 20
)

var (
	usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,32}$`)
	labelRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	pathRe     = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,=:@%/-]*$`)
)

// Validation functions return an error code ("" if valid) that the frontend translates.

func validateUsername(u string) string {
	if !usernameRe.MatchString(u) {
		return "invalid_username"
	}
	return ""
}

func validatePassword(p string) string {
	n := utf8.RuneCountInString(p)
	if n < minPasswordLen {
		return "password_too_short"
	}
	if n > maxPasswordLen {
		return "password_too_long"
	}
	return ""
}

func validateEmail(e string) string {
	if e == "" {
		return ""
	}
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e || len(e) > 254 {
		return "invalid_email"
	}
	return ""
}

// normalizeDomain lower-cases and validates a fully qualified domain name.
// Wildcards are rejected because Pi-hole local DNS records do not support them.
func normalizeDomain(d string) (string, bool) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if d == "" || len(d) > 253 {
		return "", false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", false
		}
	}
	// The top-level label must not be purely numeric (would look like an IP).
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", false
	}
	return d, true
}

// validHost accepts an IP address or a hostname (single label allowed, e.g.
// a Docker container name).
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, l := range strings.Split(strings.ToLower(h), ".") {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// domainAllowed checks the domain against the configured allow-list. An
// empty list allows every domain.
func domainAllowed(domain string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if domain == a || strings.HasSuffix(domain, "."+a) {
			return true
		}
	}
	return false
}

// parseDomainList parses a comma/whitespace separated list of domains.
// It always returns a non-nil slice so the JSON encoding is [] and never null.
func parseDomainList(s string) ([]string, string) {
	out := []string{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		d, ok := normalizeDomain(f)
		if !ok {
			return nil, "invalid_allowed_domain"
		}
		out = append(out, d)
	}
	return out, ""
}

func containsControl(s string) bool {
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\t' && r != '\r' {
			return true
		}
		if r == 0x7f {
			return true
		}
	}
	return false
}
