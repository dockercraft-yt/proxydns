package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// AuditEntry is one entry of the tamper-evident audit log.
type AuditEntry struct {
	ID       int64  `json:"id"`
	TS       int64  `json:"ts"`
	UserID   int64  `json:"userId"`
	Username string `json:"username"`
	IP       string `json:"ip"`
	Action   string `json:"action"`
	Target   string `json:"target"`
	Success  bool   `json:"success"`
	Details  string `json:"details"`
}

// macInput is the canonical form that is authenticated. Each MAC covers the
// previous entry's MAC, forming a chain: modifying, deleting or reordering an
// entry breaks verification of all following entries.
type macInput struct {
	Prev     string `json:"p"`
	ID       int64  `json:"i"`
	TS       int64  `json:"t"`
	UserID   int64  `json:"u"`
	Username string `json:"n"`
	IP       string `json:"a"`
	Action   string `json:"c"`
	Target   string `json:"g"`
	Success  bool   `json:"s"`
	Details  string `json:"d"`
}

func (s *Store) auditMAC(prev string, e *AuditEntry) string {
	data, _ := json.Marshal(macInput{prev, e.ID, e.TS, e.UserID, e.Username, e.IP, e.Action, e.Target, e.Success, e.Details})
	m := hmac.New(sha256.New, s.auditKey)
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

// AddAudit appends an entry to the audit log.
func (s *Store) AddAudit(e AuditEntry) error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if e.TS == 0 {
		e.TS = time.Now().Unix()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var prevID int64
	var prevMAC string
	err = tx.QueryRow("SELECT id, mac FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&prevID, &prevMAC)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// IDs are assigned explicitly so they can be part of the MAC.
	e.ID = prevID + 1
	mac := s.auditMAC(prevMAC, &e)
	if _, err := tx.Exec(`INSERT INTO audit_log (id, ts, user_id, username, ip, action, target, success, details, mac)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.TS, e.UserID, e.Username, e.IP, e.Action, e.Target, e.Success, e.Details, mac); err != nil {
		return err
	}
	return tx.Commit()
}

// ListAudit returns audit entries, newest first.
func (s *Store) ListAudit(limit, offset int) ([]AuditEntry, int, error) {
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT id, ts, user_id, username, ip, action, target, success, details
		FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.UserID, &e.Username, &e.IP, &e.Action, &e.Target, &e.Success, &e.Details); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// AuditVerification is the result of an integrity check.
type AuditVerification struct {
	OK       bool  `json:"ok"`
	Checked  int   `json:"checked"`
	BrokenAt int64 `json:"brokenAt,omitempty"`
}

// VerifyAudit recomputes the MAC chain over the whole log.
func (s *Store) VerifyAudit() (AuditVerification, error) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	rows, err := s.db.Query(`SELECT id, ts, user_id, username, ip, action, target, success, details, mac
		FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return AuditVerification{}, err
	}
	defer rows.Close()
	res := AuditVerification{OK: true}
	prev := ""
	var expectID int64 = 1
	for rows.Next() {
		var e AuditEntry
		var mac string
		if err := rows.Scan(&e.ID, &e.TS, &e.UserID, &e.Username, &e.IP, &e.Action, &e.Target, &e.Success, &e.Details, &mac); err != nil {
			return res, err
		}
		res.Checked++
		if e.ID != expectID || !hmac.Equal([]byte(mac), []byte(s.auditMAC(prev, &e))) {
			res.OK = false
			res.BrokenAt = e.ID
			return res, nil
		}
		prev = mac
		expectID++
	}
	return res, rows.Err()
}
