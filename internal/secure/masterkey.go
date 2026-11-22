package secure

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Key modes.
const (
	// KeyModeFile stores a random master key in a file in the data directory
	// (desktop / native use).
	KeyModeFile = "keyfile"
	// KeyModePassphrase derives the master key with Argon2id from a passphrase
	// supplied via environment variable or Docker secret (Docker use).
	KeyModePassphrase = "passphrase"
)

// MinPassphraseLen is the minimum length of the master passphrase.
const MinPassphraseLen = 16

// Argon2id parameters for the master key derivation. Stronger than for user
// passwords because it runs only once per start.
const (
	kdfTime    = 4
	kdfMemory  = 128 * 1024
	kdfThreads = 4
)

const (
	keyFileName  = "master.key"
	saltFileName = "kdf.salt"
)

// LoadMasterKey returns the 32 byte master key for the given mode.
func LoadMasterKey(dataDir, mode string, passphrase []byte) ([]byte, error) {
	switch mode {
	case KeyModeFile:
		return loadOrCreateKeyFile(filepath.Join(dataDir, keyFileName))
	case KeyModePassphrase:
		return deriveFromPassphrase(dataDir, passphrase)
	default:
		return nil, fmt.Errorf("unknown key mode %q", mode)
	}
}

func loadOrCreateKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if err := checkPrivate(path); err != nil {
			return nil, err
		}
		key, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("master key file %s is corrupt", path)
		}
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	key, err := RandomBytes(32)
	if err != nil {
		return nil, err
	}
	if err := writeNewPrivateFile(path, []byte(hex.EncodeToString(key)+"\n")); err != nil {
		return nil, fmt.Errorf("create master key: %w", err)
	}
	return key, nil
}

func deriveFromPassphrase(dataDir string, passphrase []byte) ([]byte, error) {
	if len(passphrase) < MinPassphraseLen {
		return nil, fmt.Errorf("master passphrase must be at least %d characters (PROXYDNS_MASTER_PASSPHRASE or PROXYDNS_MASTER_PASSPHRASE_FILE)", MinPassphraseLen)
	}
	saltPath := filepath.Join(dataDir, saltFileName)
	salt, err := os.ReadFile(saltPath)
	switch {
	case err == nil:
		if len(salt) != 16 {
			return nil, fmt.Errorf("salt file %s is corrupt", saltPath)
		}
	case errors.Is(err, fs.ErrNotExist):
		salt, err = RandomBytes(16)
		if err != nil {
			return nil, err
		}
		if err := writeNewPrivateFile(saltPath, salt); err != nil {
			return nil, fmt.Errorf("create salt: %w", err)
		}
	default:
		return nil, fmt.Errorf("read salt: %w", err)
	}
	return argon2.IDKey(passphrase, salt, kdfTime, kdfMemory, kdfThreads, 32), nil
}

// writeNewPrivateFile creates a file readable only by the owner. It fails if
// the file already exists, so an existing key is never overwritten.
func writeNewPrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// checkPrivate refuses key files that are readable by group or others.
// Windows uses ACLs instead of mode bits; the user profile directory is
// private by default there.
func checkPrivate(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible by other users (mode %o); run: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	return nil
}
