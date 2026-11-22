package secure

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected format %q", h)
	}
	ok, err := VerifyPassword("correct horse battery", h)
	if err != nil || !ok {
		t.Fatalf("verify failed: %v %v", ok, err)
	}
	ok, _ = VerifyPassword("wrong", h)
	if ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	for _, h := range []string{
		"", "plain", "$argon2i$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=999999999,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", // memory DoS
		"$argon2id$v=19$m=65536,t=3,p=2$!!$aGFzaA",
	} {
		if ok, err := VerifyPassword("x", h); ok || err == nil {
			t.Errorf("hash %q: expected error", h)
		}
	}
}

func TestBoxContextBinding(t *testing.T) {
	key, _ := RandomBytes(32)
	b, err := NewBox(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := b.Seal([]byte("api-secret"), "setting:a")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "api-secret") {
		t.Fatal("plaintext visible")
	}
	pt, err := b.Open(sealed, "setting:a")
	if err != nil || string(pt) != "api-secret" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if _, err := b.Open(sealed, "setting:b"); err == nil {
		t.Fatal("ciphertext accepted in other context")
	}
	other, _ := RandomBytes(32)
	b2, _ := NewBox(other)
	if _, err := b2.Open(sealed, "setting:a"); err == nil {
		t.Fatal("ciphertext accepted with other key")
	}
	tampered := sealed[:len(sealed)-2] + "AA"
	if _, err := b.Open(tampered, "setting:a"); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestKeyFileCreatedOnceAndPrivate(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadMasterKey(dir, KeyModeFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadMasterKey(dir, KeyModeFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(k1) != string(k2) || len(k1) != 32 {
		t.Fatal("key not stable")
	}
	if runtime.GOOS != "windows" {
		path := filepath.Join(dir, keyFileName)
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o", info.Mode().Perm())
		}
		os.Chmod(path, 0o644)
		if _, err := LoadMasterKey(dir, KeyModeFile, nil); err == nil {
			t.Fatal("world-readable key accepted")
		}
	}
}

func TestPassphraseMode(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadMasterKey(dir, KeyModePassphrase, []byte("short")); err == nil {
		t.Fatal("short passphrase accepted")
	}
	k1, err := LoadMasterKey(dir, KeyModePassphrase, []byte("a-very-long-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := LoadMasterKey(dir, KeyModePassphrase, []byte("a-very-long-passphrase"))
	k3, _ := LoadMasterKey(dir, KeyModePassphrase, []byte("another-long-passphrase"))
	if string(k1) != string(k2) {
		t.Fatal("derivation not deterministic")
	}
	if string(k1) == string(k3) {
		t.Fatal("different passphrases give same key")
	}
}
