// Package config reads the runtime configuration from flags and environment.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Mode describes how the application is operated.
type Mode string

const (
	// ModeServer is the web server mode (Docker or headless).
	ModeServer Mode = "server"
	// ModeDesktop is the Wails desktop window without any network listener.
	ModeDesktop Mode = "desktop"
)

// Config holds all runtime options.
type Config struct {
	Mode          Mode
	Listen        string
	DataDir       string
	KeyMode       string
	Passphrase    []byte
	TLSCert       string
	TLSKey        string
	TrustProxy    bool
	SecureCookies bool
	SessionIdle   time.Duration
	SessionMax    time.Duration
	// Args contains positional arguments after the flags.
	Args []string
}

// TLSEnabled reports whether the server terminates TLS itself.
func (c *Config) TLSEnabled() bool { return c.TLSCert != "" && c.TLSKey != "" }

// DefaultDataDir returns the per-user configuration directory.
func DefaultDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return "data"
	}
	return filepath.Join(dir, "proxydns")
}

// LoadServer parses flags and environment variables for the server mode.
func LoadServer(args []string) (*Config, error) {
	var errs []error
	fs := flag.NewFlagSet("proxydns", flag.ContinueOnError)
	cfg := &Config{Mode: ModeServer}
	fs.StringVar(&cfg.Listen, "listen", env("PROXYDNS_LISTEN", "127.0.0.1:8080"), "listen address (PROXYDNS_LISTEN)")
	fs.StringVar(&cfg.DataDir, "data-dir", env("PROXYDNS_DATA_DIR", DefaultDataDir()), "data directory (PROXYDNS_DATA_DIR)")
	fs.StringVar(&cfg.KeyMode, "key-mode", env("PROXYDNS_KEY_MODE", "keyfile"), "keyfile | passphrase (PROXYDNS_KEY_MODE)")
	fs.StringVar(&cfg.TLSCert, "tls-cert", env("PROXYDNS_TLS_CERT", ""), "TLS certificate file (PROXYDNS_TLS_CERT)")
	fs.StringVar(&cfg.TLSKey, "tls-key", env("PROXYDNS_TLS_KEY", ""), "TLS private key file (PROXYDNS_TLS_KEY)")
	fs.BoolVar(&cfg.TrustProxy, "trust-proxy", envBool("PROXYDNS_TRUST_PROXY", false, &errs), "trust X-Forwarded-For (PROXYDNS_TRUST_PROXY)")
	fs.BoolVar(&cfg.SecureCookies, "secure-cookies", envBool("PROXYDNS_SECURE_COOKIES", false, &errs), "force Secure cookies, e.g. behind HTTPS proxy (PROXYDNS_SECURE_COOKIES)")
	fs.DurationVar(&cfg.SessionIdle, "session-idle", envDuration("PROXYDNS_SESSION_IDLE", 30*time.Minute, &errs), "session idle timeout (PROXYDNS_SESSION_IDLE)")
	fs.DurationVar(&cfg.SessionMax, "session-max", envDuration("PROXYDNS_SESSION_MAX", 12*time.Hour, &errs), "absolute session lifetime (PROXYDNS_SESSION_MAX)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	cfg.Args = fs.Args()
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return nil, errors.New("tls-cert and tls-key must be set together")
	}
	if err := cfg.loadPassphrase(); err != nil {
		return nil, err
	}
	return cfg, cfg.validate()
}

// DesktopConfig returns the fixed configuration for the desktop mode.
func DesktopConfig() *Config {
	return &Config{
		Mode:        ModeDesktop,
		DataDir:     env("PROXYDNS_DATA_DIR", DefaultDataDir()),
		KeyMode:     "keyfile",
		SessionIdle: 30 * time.Minute,
		SessionMax:  12 * time.Hour,
	}
}

func (c *Config) validate() error {
	if c.KeyMode != "keyfile" && c.KeyMode != "passphrase" {
		return fmt.Errorf("invalid key mode %q (keyfile or passphrase)", c.KeyMode)
	}
	if c.SessionIdle < time.Minute || c.SessionMax < c.SessionIdle {
		return errors.New("invalid session timeouts")
	}
	return nil
}

// loadPassphrase reads the master passphrase from PROXYDNS_MASTER_PASSPHRASE_FILE
// (Docker secret) or PROXYDNS_MASTER_PASSPHRASE and removes it from the
// environment afterwards. It is deliberately not available as a flag because
// flags are visible in the process list.
func (c *Config) loadPassphrase() error {
	defer os.Unsetenv("PROXYDNS_MASTER_PASSPHRASE")
	defer os.Unsetenv("PROXYDNS_MASTER_PASSPHRASE_FILE")
	if c.KeyMode != "passphrase" {
		return nil
	}
	if path := os.Getenv("PROXYDNS_MASTER_PASSPHRASE_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read passphrase file: %w", err)
		}
		c.Passphrase = []byte(strings.TrimRight(string(data), "\r\n"))
		return nil
	}
	c.Passphrase = []byte(os.Getenv("PROXYDNS_MASTER_PASSPHRASE"))
	return nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool, errs *[]error) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: invalid boolean %q", key, v))
		return def
	}
	return b
}

func envDuration(key string, def time.Duration, errs *[]error) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: invalid duration %q", key, v))
		return def
	}
	return d
}
