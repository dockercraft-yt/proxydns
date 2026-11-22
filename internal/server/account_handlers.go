package server

import (
	"net/http"

	"proxydns/internal/secure"
)

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	u := a.user
	if u.PasswordHash != "" {
		ok, _ := secure.VerifyPassword(in.Current, u.PasswordHash)
		if !ok {
			s.audit(r, u, "password_change", u.Username, false, "wrong current password")
			writeError(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
	}
	if code := validatePassword(in.New); code != "" {
		writeError(w, http.StatusBadRequest, code)
		return
	}
	hash, err := secure.HashPassword(in.New)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	u.PasswordHash = hash
	if err := s.store.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	// Log out all other sessions of this user.
	_ = s.store.DeleteUserSessions(u.ID, a.sess.IDHash)
	s.audit(r, u, "password_change", u.Username, true, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request, a *authCtx) {
	u := a.user
	if u.TOTPEnabled {
		writeError(w, http.StatusConflict, "totp_already_enabled")
		return
	}
	key, qr, err := generateTOTPKey(u.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	sealed, err := s.store.SealUserSecret(u.ID, totpPurpose, key.Secret())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	u.TOTPPending = sealed
	if err := s.store.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret": key.Secret(),
		"url":    key.URL(),
		"qr":     qr,
	})
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	u := a.user
	if u.TOTPEnabled {
		writeError(w, http.StatusConflict, "totp_already_enabled")
		return
	}
	if u.TOTPPending == "" {
		writeError(w, http.StatusBadRequest, "totp_not_started")
		return
	}
	if !s.checkUserTOTP(u, u.TOTPPending, in.Code) {
		s.audit(r, u, "totp_enable", u.Username, false, "wrong code")
		writeError(w, http.StatusBadRequest, "invalid_code")
		return
	}
	u.TOTPSecret = u.TOTPPending
	u.TOTPPending = ""
	u.TOTPEnabled = true
	if err := s.store.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	_ = s.store.DeleteUserSessions(u.ID, a.sess.IDHash)
	s.audit(r, u, "totp_enable", u.Username, true, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	u := a.user
	if !u.TOTPEnabled {
		writeError(w, http.StatusBadRequest, "totp_not_enabled")
		return
	}
	if u.PasswordHash != "" {
		if ok, _ := secure.VerifyPassword(in.Password, u.PasswordHash); !ok {
			s.audit(r, u, "totp_disable", u.Username, false, "wrong password")
			writeError(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
	}
	if !s.checkUserTOTP(u, u.TOTPSecret, in.Code) {
		s.audit(r, u, "totp_disable", u.Username, false, "wrong code")
		writeError(w, http.StatusBadRequest, "invalid_code")
		return
	}
	u.TOTPEnabled = false
	u.TOTPSecret = ""
	u.TOTPPending = ""
	if err := s.store.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.audit(r, u, "totp_disable", u.Username, true, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
