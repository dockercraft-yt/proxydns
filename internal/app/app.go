// Package app contains the startup code shared by the server and desktop binaries.
package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"proxydns/internal/config"
	"proxydns/internal/secure"
	"proxydns/internal/store"
)

// Version is set at build time via -ldflags "-X proxydns/internal/app.Version=...".
var Version = "dev"

// OpenStore prepares the data directory, loads the master key and opens the
// database. The master key is wiped from memory after the derived keys are
// created.
func OpenStore(cfg *config.Config) (*store.Store, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	if runtime.GOOS != "windows" {
		// Also tighten a pre-existing directory (e.g. created by Docker or by hand).
		if err := os.Chmod(cfg.DataDir, 0o700); err != nil {
			return nil, fmt.Errorf("secure data dir: %w", err)
		}
	}
	key, err := secure.LoadMasterKey(cfg.DataDir, cfg.KeyMode, cfg.Passphrase)
	secure.Wipe(cfg.Passphrase)
	cfg.Passphrase = nil
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(key)

	encKey := secure.DeriveSubkey(key, "proxydns-encryption-v1")
	auditKey := secure.DeriveSubkey(key, "proxydns-audit-v1")
	box, err := secure.NewBox(encKey)
	secure.Wipe(encKey)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "proxydns.db"), box, auditKey)
	if err != nil {
		return nil, err
	}
	if err := st.CheckMasterKey(); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}
