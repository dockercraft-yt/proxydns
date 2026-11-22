package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"image/png"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"proxydns/internal/store"
)

const totpIssuer = "ProxyDNS Manager"

// totpPurpose is the encryption context for TOTP seeds (pending and active).
const totpPurpose = "totp"

var totpOpts = totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// matchTOTP checks a code against the secret for the current step and one
// step of clock skew in each direction. It returns the matching step; steps
// not newer than lastStep are rejected (no code reuse).
func matchTOTP(secret, code string, lastStep int64, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	for _, off := range []int64{0, -1, 1} {
		t := now.Add(time.Duration(off*30) * time.Second)
		step := t.Unix() / 30
		if step <= lastStep {
			continue
		}
		expected, err := totp.GenerateCodeCustom(secret, t, totpOpts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// checkUserTOTP validates a code against an encrypted seed of the user and
// atomically records the used step.
func (s *Server) checkUserTOTP(u *store.User, sealedSecret, code string) bool {
	if sealedSecret == "" {
		return false
	}
	secret, err := s.store.OpenUserSecret(u.ID, totpPurpose, sealedSecret)
	if err != nil {
		s.log.Error("cannot decrypt TOTP secret", "user", u.Username, "err", err)
		return false
	}
	step, ok := matchTOTP(secret, code, u.TOTPLastStep, time.Now())
	if !ok {
		return false
	}
	updated, err := s.store.SetTOTPLastStep(u.ID, step)
	if err != nil || !updated {
		return false
	}
	u.TOTPLastStep = step
	return true
}

func generateTOTPKey(username string) (*otp.Key, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: username,
		Period:      30,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, "", err
	}
	img, err := key.Image(240, 240)
	if err != nil {
		return nil, "", err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, "", err
	}
	return key, "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
