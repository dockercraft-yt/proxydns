// Package secure contains the cryptographic building blocks of the application:
// Argon2id password hashing, AES-256-GCM encryption of secrets, master key
// handling and random token generation.
package secure

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for user passwords (OWASP recommendation level).
const (
	pwTime    = 3
	pwMemory  = 64 * 1024 // KiB
	pwThreads = 2
	pwKeyLen  = 32
	pwSaltLen = 16
)

// ErrInvalidHash is returned when a stored password hash cannot be parsed.
var ErrInvalidHash = errors.New("invalid password hash format")

var b64 = base64.RawStdEncoding

// hashSlots limits concurrent Argon2 computations, each of which needs
// ~64 MiB RAM. This prevents memory exhaustion by parallel login attempts.
var hashSlots = make(chan struct{}, 4)

func argonKey(password, salt []byte, t, m uint32, p uint8, keyLen uint32) []byte {
	hashSlots <- struct{}{}
	defer func() { <-hashSlots }()
	return argon2.IDKey(password, salt, t, m, p, keyLen)
}

// HashPassword returns an Argon2id hash in PHC string format.
func HashPassword(password string) (string, error) {
	salt, err := RandomBytes(pwSaltLen)
	if err != nil {
		return "", err
	}
	key := argonKey([]byte(password), salt, pwTime, pwMemory, pwThreads, pwKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, pwMemory, pwTime, pwThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an Argon2id PHC hash in constant time.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrInvalidHash
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, ErrInvalidHash
	}
	// Reject absurd parameters so a manipulated DB cannot cause resource exhaustion.
	if m < 8*1024 || m > 1024*1024 || t < 1 || t > 16 || p < 1 || p > 16 {
		return false, ErrInvalidHash
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false, ErrInvalidHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false, ErrInvalidHash
	}
	got := argonKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// DummyVerify performs a password verification against a fixed hash. It is
// used for unknown usernames so that response timing does not reveal whether
// an account exists.
func DummyVerify(password string) {
	dummyOnce.Do(func() {
		dummyHash, _ = HashPassword("timing-equalisation-dummy")
	})
	_, _ = VerifyPassword(password, dummyHash)
}

// RandomBytes returns n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
