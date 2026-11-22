// Package store persists users, sessions, settings and the audit log in SQLite.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"proxydns/internal/secure"

	_ "modernc.org/sqlite" // pure Go SQLite driver, no CGO required
)

var (
	// ErrNotFound is returned when a record does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned on unique constraint violations.
	ErrConflict = errors.New("already exists")
	// ErrWrongMasterKey is returned when the master key does not match the DB.
	ErrWrongMasterKey = errors.New("master key does not match this database (wrong passphrase or key file?)")
)

// Store wraps the SQLite database.
type Store struct {
	db       *sql.DB
	box      *secure.Box
	auditKey []byte
	auditMu  sync.Mutex
}

// Open opens (and migrates) the database at path.
func Open(path string, box *secure.Box, auditKey []byte) (*Store, error) {
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A single connection avoids SQLITE_BUSY between writers; load is tiny.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o600)
	}
	s := &Store{db: db, box: box, auditKey: auditKey}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// migrations are applied in order; the index+1 is stored in PRAGMA user_version.
var migrations = [][]string{
	{
		`CREATE TABLE users (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			username       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
			password_hash  TEXT    NOT NULL DEFAULT '',
			role           TEXT    NOT NULL CHECK (role IN ('admin','user')),
			email          TEXT    NOT NULL DEFAULT '',
			oidc_subject   TEXT    UNIQUE,
			totp_enabled   INTEGER NOT NULL DEFAULT 0,
			totp_secret    TEXT    NOT NULL DEFAULT '',
			totp_pending   TEXT    NOT NULL DEFAULT '',
			totp_last_step INTEGER NOT NULL DEFAULT 0,
			disabled       INTEGER NOT NULL DEFAULT 0,
			failed_logins  INTEGER NOT NULL DEFAULT 0,
			locked_until   INTEGER NOT NULL DEFAULT 0,
			created_at     INTEGER NOT NULL,
			updated_at     INTEGER NOT NULL
		)`,
		`CREATE TABLE sessions (
			id_hash      TEXT    PRIMARY KEY,
			user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			csrf         TEXT    NOT NULL,
			mfa_pending  INTEGER NOT NULL DEFAULT 0,
			mfa_attempts INTEGER NOT NULL DEFAULT 0,
			created_at   INTEGER NOT NULL,
			last_seen    INTEGER NOT NULL,
			expires_at   INTEGER NOT NULL,
			ip           TEXT    NOT NULL DEFAULT '',
			user_agent   TEXT    NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX sessions_user ON sessions(user_id)`,
		`CREATE TABLE settings (
			key       TEXT    PRIMARY KEY,
			value     TEXT    NOT NULL,
			encrypted INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE audit_log (
			id       INTEGER PRIMARY KEY AUTOINCREMENT,
			ts       INTEGER NOT NULL,
			user_id  INTEGER NOT NULL DEFAULT 0,
			username TEXT    NOT NULL DEFAULT '',
			ip       TEXT    NOT NULL DEFAULT '',
			action   TEXT    NOT NULL,
			target   TEXT    NOT NULL DEFAULT '',
			success  INTEGER NOT NULL,
			details  TEXT    NOT NULL DEFAULT '',
			mac      TEXT    NOT NULL
		)`,
	},
}

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this program supports (%d)", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range migrations[i] {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return err
			}
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

const keyCheckSetting = "_keycheck"
const keyCheckValue = "proxydns-keycheck-v1"

// CheckMasterKey verifies that the master key matches the database. On a
// fresh database a check value is written.
func (s *Store) CheckMasterKey() error {
	var value string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = ?", keyCheckSetting).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		sealed, err := s.box.Seal([]byte(keyCheckValue), "setting:"+keyCheckSetting)
		if err != nil {
			return err
		}
		_, err = s.db.Exec("INSERT INTO settings(key, value, encrypted) VALUES (?, ?, 1)", keyCheckSetting, sealed)
		return err
	}
	if err != nil {
		return err
	}
	pt, err := s.box.Open(value, "setting:"+keyCheckSetting)
	if err != nil || string(pt) != keyCheckValue {
		return ErrWrongMasterKey
	}
	return nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
