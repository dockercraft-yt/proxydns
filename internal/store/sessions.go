package store

import (
	"database/sql"
	"errors"
)

// Session is a login session. Only the SHA-256 hash of the token is stored.
type Session struct {
	IDHash      string
	UserID      int64
	CSRF        string
	MFAPending  bool
	MFAAttempts int
	CreatedAt   int64
	LastSeen    int64
	ExpiresAt   int64
	IP          string
	UserAgent   string
}

// CreateSession stores a new session.
func (s *Store) CreateSession(se *Session) error {
	_, err := s.db.Exec(`INSERT INTO sessions (id_hash, user_id, csrf, mfa_pending, mfa_attempts,
		created_at, last_seen, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`,
		se.IDHash, se.UserID, se.CSRF, se.MFAPending, se.CreatedAt, se.LastSeen, se.ExpiresAt, se.IP, se.UserAgent)
	return err
}

// GetSession loads a session by token hash.
func (s *Store) GetSession(idHash string) (*Session, error) {
	se := &Session{}
	err := s.db.QueryRow(`SELECT id_hash, user_id, csrf, mfa_pending, mfa_attempts, created_at,
		last_seen, expires_at, ip, user_agent FROM sessions WHERE id_hash = ?`, idHash).
		Scan(&se.IDHash, &se.UserID, &se.CSRF, &se.MFAPending, &se.MFAAttempts, &se.CreatedAt,
			&se.LastSeen, &se.ExpiresAt, &se.IP, &se.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return se, err
}

// TouchSession updates the last activity timestamp.
func (s *Store) TouchSession(idHash string, now int64) error {
	_, err := s.db.Exec("UPDATE sessions SET last_seen = ? WHERE id_hash = ?", now, idHash)
	return err
}

// IncrementMFAAttempts increments and returns the TOTP attempt counter.
func (s *Store) IncrementMFAAttempts(idHash string) (int, error) {
	if _, err := s.db.Exec("UPDATE sessions SET mfa_attempts = mfa_attempts + 1 WHERE id_hash = ?", idHash); err != nil {
		return 0, err
	}
	var n int
	err := s.db.QueryRow("SELECT mfa_attempts FROM sessions WHERE id_hash = ?", idHash).Scan(&n)
	return n, err
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(idHash string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id_hash = ?", idHash)
	return err
}

// DeleteUserSessions removes all sessions of a user except the given one.
func (s *Store) DeleteUserSessions(userID int64, exceptHash string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE user_id = ? AND id_hash <> ?", userID, exceptHash)
	return err
}

// DeleteExpiredSessions removes sessions past their absolute lifetime or idle timeout.
func (s *Store) DeleteExpiredSessions(now, idleCutoff int64) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE expires_at <= ? OR last_seen < ?", now, idleCutoff)
	return err
}
