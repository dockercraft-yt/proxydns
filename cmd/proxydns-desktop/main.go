//go:build desktop

// Command proxydns-desktop runs the application in a native window
// (Wails). The HTTP handler is served directly through the WebView's asset
// server; no network port is opened.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"proxydns/internal/app"
	"proxydns/internal/config"
	"proxydns/internal/server"
)

// icon is shown in the window title / taskbar on Linux.
//
//go:embed assets/icon.png
var icon []byte

func main() {
	cfg := config.DesktopConfig()
	logger, closeLog := openLog(cfg.DataDir)
	defer closeLog()

	var handler http.Handler
	onShutdown := func(context.Context) {}

	st, err := app.OpenStore(cfg)
	if err != nil {
		logger.Error("startup failed", "err", err)
		handler = errorPage(err, cfg.DataDir)
	} else {
		srv := server.New(cfg, st, logger, app.Version)
		handler = srv.Handler()
		onShutdown = func(context.Context) {
			srv.Close()
			st.Close()
		}
		logger.Info("desktop started", "version", app.Version, "data", cfg.DataDir)
	}

	err = wails.Run(&options.App{
		Title:     "ProxyDNS Manager",
		Width:     1280,
		Height:    860,
		MinWidth:  900,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Handler: handler,
		},
		OnShutdown: onShutdown,
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "proxydns-5f0c6a2e",
		},
		EnableDefaultContextMenu: false,
		Linux: &linux.Options{
			ProgramName: "proxydns",
			Icon:        icon,
		},
		Windows: &windows.Options{},
	})
	if err != nil {
		logger.Error("window failed", "err", err)
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// openLog writes logs to <data>/proxydns.log because a GUI app has no console.
func openLog(dataDir string) (*slog.Logger, func()) {
	var w io.Writer = os.Stderr
	closeFn := func() {}
	if err := os.MkdirAll(dataDir, 0o700); err == nil {
		if f, err := os.OpenFile(filepath.Join(dataDir, "proxydns.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			w = io.MultiWriter(os.Stderr, f)
			closeFn = func() { f.Close() }
		}
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})), closeFn
}

// errorPage shows a startup error (e.g. corrupt key file) inside the window.
func errorPage(err error, dataDir string) http.Handler {
	body := fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>ProxyDNS Manager</title></head>
<body style="font-family:system-ui,sans-serif;padding:2rem;max-width:720px">
<h1>Start fehlgeschlagen / Startup failed</h1>
<p><code>%s</code></p>
<p>Datenverzeichnis / data directory: <code>%s</code></p>
<p>Details: proxydns.log</p></body></html>`, html.EscapeString(err.Error()), html.EscapeString(dataDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		io.WriteString(w, body)
	})
}
