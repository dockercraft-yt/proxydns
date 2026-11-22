package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const boxPrefix = "v1:"

// ErrDecrypt is returned when a ciphertext cannot be decrypted (wrong key,
// manipulated data or wrong context).
var ErrDecrypt = errors.New("decryption failed")

// Box encrypts and decrypts secrets with AES-256-GCM.
//
// Every ciphertext is bound to a context string (additional authenticated
// data). A ciphertext copied to another DB field fails to decrypt.
type Box struct {
	aead cipher.AEAD
}

// NewBox creates a Box from a 32 byte key.
func NewBox(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext bound to the given context.
func (b *Box) Seal(plaintext []byte, context string) (string, error) {
	nonce, err := RandomBytes(b.aead.NonceSize())
	if err != nil {
		return "", err
	}
	ct := b.aead.Seal(nonce, nonce, plaintext, []byte(context))
	return boxPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// Open decrypts a value produced by Seal with the same context.
func (b *Box) Open(sealed, context string) ([]byte, error) {
	if !strings.HasPrefix(sealed, boxPrefix) {
		return nil, ErrDecrypt
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, boxPrefix))
	if err != nil {
		return nil, ErrDecrypt
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns+b.aead.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := b.aead.Open(nil, raw[:ns], raw[ns:], []byte(context))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// DeriveSubkey derives an independent key for a specific purpose from the
// master key (HMAC-SHA256 based KDF).
func DeriveSubkey(master []byte, label string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte(label))
	return m.Sum(nil)
}

// RandomToken returns a URL-safe random token with n bytes of entropy.
func RandomToken(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the SHA-256 hex digest of a token. Session tokens are
// only stored hashed so a leaked database does not contain usable sessions.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Equal compares two strings in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Wipe overwrites a byte slice with zeros.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
