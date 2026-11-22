package store

import (
	"database/sql"
	"errors"
	"time"
)

// Roles.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// User is an application account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string // Argon2id PHC string, empty for OIDC-only accounts
	Role         string
	Email        string
	OIDCSubject  string
	TOTPEnabled  bool
	TOTPSecret   string // encrypted
	TOTPPending  string // encrypted, set during TOTP enrolment
	TOTPLastStep int64  // last accepted TOTP time step (replay protection)
	Disabled     bool
	FailedLogins int
	LockedUntil  int64
	CreatedAt    int64
	UpdatedAt    int64
}

// IsAdmin reports whether the user has the admin role.
func (u *User) IsAdmin() bool { return u.Role == RoleAdmin }

const userCols = `id, username, password_hash, role, email, COALESCE(oidc_subject, ''),
	totp_enabled, totp_secret, totp_pending, totp_last_step, disabled,
	failed_logins, locked_until, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func scanUser(row scanner) (*User, error) {
	u := &User{}
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Email, &u.OIDCSubject,
		&u.TOTPEnabled, &u.TOTPSecret, &u.TOTPPending, &u.TOTPLastStep, &u.Disabled,
		&u.FailedLogins, &u.LockedUntil, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) getUser(where string, arg any) (*User, error) {
	return scanUser(s.db.QueryRow("SELECT "+userCols+" FROM users WHERE "+where, arg))
}

// GetUserByID loads a user by ID.
func (s *Store) GetUserByID(id int64) (*User, error) { return s.getUser("id = ?", id) }

// GetUserByUsername loads a user by username (case-insensitive).
func (s *Store) GetUserByUsername(name string) (*User, error) {
	return s.getUser("username = ?", name)
}

// GetUserByOIDCSubject loads a user linked to an OIDC subject.
func (s *Store) GetUserByOIDCSubject(sub string) (*User, error) {
	return s.getUser("oidc_subject = ?", sub)
}

// FindUsersByEmail returns all users with the given e-mail (case-insensitive).
func (s *Store) FindUsersByEmail(email string) ([]*User, error) {
	return s.queryUsers("SELECT "+userCols+" FROM users WHERE email <> '' AND lower(email) = lower(?)", email)
}

// ListUsers returns all users ordered by username.
func (s *Store) ListUsers() ([]*User, error) {
	return s.queryUsers("SELECT " + userCols + " FROM users ORDER BY username")
}

func (s *Store) queryUsers(query string, args ...any) ([]*User, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers returns the number of users.
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

// CountActiveAdmins returns the number of enabled admins.
func (s *Store) CountActiveAdmins() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0").Scan(&n)
	return n, err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// CreateUser inserts a new user and sets its ID.
func (s *Store) CreateUser(u *User) error {
	now := time.Now().Unix()
	u.CreatedAt, u.UpdatedAt = now, now
	res, err := s.db.Exec(`INSERT INTO users (username, password_hash, role, email, oidc_subject,
		totp_enabled, totp_secret, totp_pending, totp_last_step, disabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Username, u.PasswordHash, u.Role, u.Email, nullable(u.OIDCSubject),
		u.TOTPEnabled, u.TOTPSecret, u.TOTPPending, u.TOTPLastStep, u.Disabled, now, now)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	u.ID, err = res.LastInsertId()
	return err
}

// UpdateUser writes all mutable fields of a user.
func (s *Store) UpdateUser(u *User) error {
	u.UpdatedAt = time.Now().Unix()
	res, err := s.db.Exec(`UPDATE users SET password_hash = ?, role = ?, email = ?, oidc_subject = ?,
		totp_enabled = ?, totp_secret = ?, totp_pending = ?, totp_last_step = ?, disabled = ?,
		failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?`,
		u.PasswordHash, u.Role, u.Email, nullable(u.OIDCSubject),
		u.TOTPEnabled, u.TOTPSecret, u.TOTPPending, u.TOTPLastStep, u.Disabled,
		u.FailedLogins, u.LockedUntil, u.UpdatedAt, u.ID)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser removes a user (sessions are removed by cascade).
func (s *Store) DeleteUser(id int64) error {
	res, err := s.db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RegisterFailedLogin increments the failure counter and locks the account
// for lockFor once maxFailures is reached. It returns true if the account is
// now locked.
func (s *Store) RegisterFailedLogin(id int64, maxFailures int, lockFor time.Duration) (bool, error) {
	until := time.Now().Add(lockFor).Unix()
	_, err := s.db.Exec(`UPDATE users SET
		locked_until  = CASE WHEN failed_logins + 1 >= ? THEN ? ELSE locked_until END,
		failed_logins = CASE WHEN failed_logins + 1 >= ? THEN 0 ELSE failed_logins + 1 END
		WHERE id = ?`, maxFailures, until, maxFailures, id)
	if err != nil {
		return false, err
	}
	var locked int64
	err = s.db.QueryRow("SELECT locked_until FROM users WHERE id = ?", id).Scan(&locked)
	return locked > time.Now().Unix(), err
}

// ResetFailedLogins clears the failure counter after a successful login.
func (s *Store) ResetFailedLogins(id int64) error {
	_, err := s.db.Exec("UPDATE users SET failed_logins = 0 WHERE id = ?", id)
	return err
}

// SetTOTPLastStep stores the last accepted TOTP step. It only succeeds if the
// step is newer than the stored one, which makes code reuse impossible even
// with concurrent requests.
func (s *Store) SetTOTPLastStep(id, step int64) (bool, error) {
	res, err := s.db.Exec("UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?", step, id, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
