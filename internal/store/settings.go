package store

import (
	"database/sql"
	"errors"
	"strconv"
)

func settingContext(key string) string { return "setting:" + key }

// Settings returns all plain (non-encrypted) settings.
func (s *Store) Settings() (map[string]string, error) {
	rows, err := s.db.Query("SELECT key, value FROM settings WHERE encrypted = 0")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// Secret returns a decrypted secret setting, or "" if it is not set.
func (s *Store) Secret(key string) (string, error) {
	var sealed string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = ? AND encrypted = 1", key).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	pt, err := s.box.Open(sealed, settingContext(key))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// HasSecret reports whether a secret setting is stored.
func (s *Store) HasSecret(key string) (bool, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM settings WHERE key = ? AND encrypted = 1", key).Scan(&n)
	return n > 0, err
}

// SaveSettings stores plain settings and secrets in one transaction.
// A nil secret pointer leaves the secret unchanged, an empty string removes it.
func (s *Store) SaveSettings(plain map[string]string, secrets map[string]*string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, v := range plain {
		if _, err := tx.Exec(`INSERT INTO settings(key, value, encrypted) VALUES (?, ?, 0)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, encrypted = 0`, k, v); err != nil {
			return err
		}
	}
	for k, v := range secrets {
		if v == nil {
			continue
		}
		if *v == "" {
			if _, err := tx.Exec("DELETE FROM settings WHERE key = ?", k); err != nil {
				return err
			}
			continue
		}
		sealed, err := s.box.Seal([]byte(*v), settingContext(k))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO settings(key, value, encrypted) VALUES (?, ?, 1)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, encrypted = 1`, k, sealed); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SealUserSecret encrypts a per-user secret (e.g. TOTP seed).
func (s *Store) SealUserSecret(userID int64, purpose, value string) (string, error) {
	return s.box.Seal([]byte(value), userContext(userID, purpose))
}

// OpenUserSecret decrypts a per-user secret.
func (s *Store) OpenUserSecret(userID int64, purpose, sealed string) (string, error) {
	pt, err := s.box.Open(sealed, userContext(userID, purpose))
	return string(pt), err
}

func userContext(userID int64, purpose string) string {
	return "user:" + strconv.FormatInt(userID, 10) + ":" + purpose
}
