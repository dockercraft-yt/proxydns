// Command proxydns runs the web server (Docker / headless).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"proxydns/internal/app"
	"proxydns/internal/config"
	"proxydns/internal/secure"
	"proxydns/internal/server"
	"proxydns/internal/store"
)

const usage = `ProxyDNS Manager – Pi-hole v6 + Nginx Proxy Manager

Usage:
  proxydns [serve] [flags]          start the web server
  proxydns reset-password <user>    set a new random password
  proxydns reset-mfa <user>         disable TOTP for a user
  proxydns healthcheck              exit 0 if the server is healthy
  proxydns version

Run "proxydns serve -h" for flags. All flags can be set via PROXYDNS_* environment variables.
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "reset-password":
		err = resetPassword(args)
	case "reset-mfa":
		err = resetMFA(args)
	case "healthcheck":
		os.Exit(healthcheck())
	case "version":
		fmt.Println(app.Version)
	case "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	cfg, err := config.LoadServer(args)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	st, err := app.OpenStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	srv := server.New(cfg, st, logger, app.Version)
	defer srv.Close()

	n, err := st.CountUsers()
	if err != nil {
		return err
	}
	if n == 0 {
		token, err := secure.RandomToken(18)
		if err != nil {
			return err
		}
		srv.SetSetupToken(token)
		fmt.Printf("\n==================================================================\n"+
			" FIRST START – no user exists yet.\n"+
			" Open the web interface and enter this one-time setup code:\n\n"+
			"     %s\n\n"+
			" The code is valid until the first admin has been created.\n"+
			"==================================================================\n\n", token)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	hs := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	errCh := make(chan error, 1)
	go func() {
		if cfg.TLSEnabled() {
			hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			errCh <- hs.ServeTLS(ln, cfg.TLSCert, cfg.TLSKey)
		} else {
			errCh <- hs.Serve(ln)
		}
	}()
	scheme := "http"
	if cfg.TLSEnabled() {
		scheme = "https"
	}
	logger.Info("ProxyDNS Manager started", "version", app.Version, "url", scheme+"://"+ln.Addr().String(), "data", cfg.DataDir, "keyMode", cfg.KeyMode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	logger.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return hs.Shutdown(shutCtx)
}

// openForCLI opens the store for the maintenance commands.
func openForCLI(args []string) (*store.Store, *store.User, error) {
	cfg, err := config.LoadServer(args)
	if err != nil {
		return nil, nil, err
	}
	if len(cfg.Args) != 1 {
		return nil, nil, errors.New("exactly one username is required")
	}
	st, err := app.OpenStore(cfg)
	if err != nil {
		return nil, nil, err
	}
	u, err := st.GetUserByUsername(cfg.Args[0])
	if err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("user %q: %w", cfg.Args[0], err)
	}
	return st, u, nil
}

func resetPassword(args []string) error {
	st, u, err := openForCLI(args)
	if err != nil {
		return err
	}
	defer st.Close()
	pw, err := secure.RandomToken(18)
	if err != nil {
		return err
	}
	hash, err := secure.HashPassword(pw)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	u.LockedUntil = 0
	u.FailedLogins = 0
	if err := st.UpdateUser(u); err != nil {
		return err
	}
	_ = st.DeleteUserSessions(u.ID, "")
	_ = st.AddAudit(store.AuditEntry{UserID: u.ID, Username: u.Username, IP: "cli", Action: "cli_reset_password", Target: u.Username, Success: true})
	fmt.Printf("New password for %s: %s\nPlease change it after logging in.\n", u.Username, pw)
	return nil
}

func resetMFA(args []string) error {
	st, u, err := openForCLI(args)
	if err != nil {
		return err
	}
	defer st.Close()
	u.TOTPEnabled = false
	u.TOTPSecret = ""
	u.TOTPPending = ""
	if err := st.UpdateUser(u); err != nil {
		return err
	}
	_ = st.DeleteUserSessions(u.ID, "")
	_ = st.AddAudit(store.AuditEntry{UserID: u.ID, Username: u.Username, IP: "cli", Action: "cli_reset_mfa", Target: u.Username, Success: true})
	fmt.Printf("TOTP disabled for %s.\n", u.Username)
	return nil
}

// healthcheck is used by the Docker HEALTHCHECK (the image has no curl).
func healthcheck() int {
	listen := os.Getenv("PROXYDNS_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:8080"
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 1
	}
	scheme := "http"
	tr := &http.Transport{}
	if os.Getenv("PROXYDNS_TLS_CERT") != "" {
		scheme = "https"
		// Local loopback check only; the certificate is issued for the LAN name.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	c := &http.Client{Timeout: 3 * time.Second, Transport: tr}
	resp, err := c.Get(scheme + "://127.0.0.1:" + port + "/api/health")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
