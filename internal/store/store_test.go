package store

import (
	"path/filepath"
	"testing"
	"time"

	"proxydns/internal/secure"
)

func newTestStore(t *testing.T, key []byte) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	return openAt(t, path, key), path
}

func openAt(t *testing.T, path string, key []byte) *Store {
	t.Helper()
	box, err := secure.NewBox(key)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, box, secure.DeriveSubkey(key, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestPragmasApplied(t *testing.T) {
	key, _ := secure.RandomBytes(32)
	st, _ := newTestStore(t, key)
	var fk int
	if err := st.db.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys = %d (%v)", fk, err)
	}
}

func TestMasterKeyCheck(t *testing.T) {
	key, _ := secure.RandomBytes(32)
	st, path := newTestStore(t, key)
	if err := st.CheckMasterKey(); err != nil {
		t.Fatal(err)
	}
	st.Close()
	other, _ := secure.RandomBytes(32)
	st2 := openAt(t, path, other)
	if err := st2.CheckMasterKey(); err != ErrWrongMasterKey {
		t.Fatalf("expected ErrWrongMasterKey, got %v", err)
	}
}

func TestSecretsEncryptedAtRest(t *testing.T) {
	key, _ := secure.RandomBytes(32)
	st, _ := newTestStore(t, key)
	pw := "super-secret-app-password"
	if err := st.SaveSettings(map[string]string{"pihole.url": "https://pi.hole"}, map[string]*string{"pihole.password": &pw}); err != nil {
		t.Fatal(err)
	}
	var raw string
	st.db.QueryRow("SELECT value FROM settings WHERE key = 'pihole.password'").Scan(&raw)
	if raw == pw || raw == "" {
		t.Fatalf("secret stored in plaintext: %q", raw)
	}
	got, err := st.Secret("pihole.password")
	if err != nil || got != pw {
		t.Fatalf("Secret = %q, %v", got, err)
	}
	plain, _ := st.Settings()
	if _, ok := plain["pihole.password"]; ok {
		t.Fatal("secret returned by Settings()")
	}
	// nil leaves unchanged, empty deletes
	if err := st.SaveSettings(nil, map[string]*string{"pihole.password": nil}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Secret("pihole.password"); got != pw {
		t.Fatal("nil pointer changed the secret")
	}
	empty := ""
	st.SaveSettings(nil, map[string]*string{"pihole.password": &empty})
	if has, _ := st.HasSecret("pihole.password"); has {
		t.Fatal("secret not removed")
	}
}

func TestUsersAndLockout(t *testing.T) {
	key, _ := secure.RandomBytes(32)
	st, _ := newTestStore(t, key)
	u := &User{Username: "Admin", Role: RoleAdmin}
	if err := st.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(&User{Username: "admin", Role: RoleUser}); err != ErrConflict {
		t.Fatalf("case-insensitive duplicate allowed: %v", err)
	}
	for i := 0; i < 4; i++ {
		locked, _ := st.RegisterFailedLogin(u.ID, 5, time.Minute)
		if locked {
			t.Fatalf("locked after %d failures", i+1)
		}
	}
	locked, _ := st.RegisterFailedLogin(u.ID, 5, time.Minute)
	if !locked {
		t.Fatal("not locked after 5 failures")
	}
	// TOTP step replay protection
	ok, _ := st.SetTOTPLastStep(u.ID, 100)
	if !ok {
		t.Fatal("first step rejected")
	}
	ok, _ = st.SetTOTPLastStep(u.ID, 100)
	if ok {
		t.Fatal("same step accepted twice")
	}
	// sessions cascade on delete
	st.CreateSession(&Session{IDHash: "h", UserID: u.ID, CSRF: "c", CreatedAt: 1, LastSeen: 1, ExpiresAt: 2})
	st.DeleteUser(u.ID)
	if _, err := st.GetSession("h"); err != ErrNotFound {
		t.Fatal("session not removed with user")
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	key, _ := secure.RandomBytes(32)
	st, _ := newTestStore(t, key)
	for i := 0; i < 5; i++ {
		if err := st.AddAudit(AuditEntry{Action: "test", Target: "x", Success: true}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := st.VerifyAudit()
	if err != nil || !res.OK || res.Checked != 5 {
		t.Fatalf("clean log not OK: %+v %v", res, err)
	}
	st.db.Exec("UPDATE audit_log SET success = 0 WHERE id = 3")
	res, _ = st.VerifyAudit()
	if res.OK || res.BrokenAt != 3 {
		t.Fatalf("modification not detected: %+v", res)
	}
	st.db.Exec("UPDATE audit_log SET success = 1 WHERE id = 3")
	st.db.Exec("DELETE FROM audit_log WHERE id = 2")
	res, _ = st.VerifyAudit()
	if res.OK {
		t.Fatal("deletion not detected")
	}
}
