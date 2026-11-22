package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"proxydns/internal/secure"
	"proxydns/internal/store"
)

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request, a *authCtx) {
	users, err := s.store.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	out := make([]userDTO, 0, len(users))
	for _, u := range users {
		out = append(out, toUserDTO(u))
	}
	writeJSON(w, http.StatusOK, out)
}

func validRole(r string) bool { return r == store.RoleAdmin || r == store.RoleUser }

// emailInUse reports whether another user already has this e-mail. E-mails
// must be unique because they are used to link OIDC logins.
func (s *Server) emailInUse(email string, exceptID int64) (bool, error) {
	if email == "" {
		return false, nil
	}
	users, err := s.store.FindUsersByEmail(email)
	if err != nil {
		return false, err
	}
	for _, u := range users {
		if u.ID != exceptID {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Email    string `json:"email"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)
	if code := validateUsername(in.Username); code != "" {
		writeError(w, http.StatusBadRequest, code)
		return
	}
	if !validRole(in.Role) {
		writeError(w, http.StatusBadRequest, "invalid_role")
		return
	}
	if code := validateEmail(in.Email); code != "" {
		writeError(w, http.StatusBadRequest, code)
		return
	}
	// A user needs either a password or an e-mail for OIDC login.
	if in.Password == "" && (in.Email == "" || s.desktop()) {
		writeError(w, http.StatusBadRequest, "password_or_email_required")
		return
	}
	if inUse, err := s.emailInUse(in.Email, 0); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	} else if inUse {
		writeError(w, http.StatusConflict, "email_in_use")
		return
	}
	u := &store.User{Username: in.Username, Role: in.Role, Email: in.Email}
	if in.Password != "" {
		if code := validatePassword(in.Password); code != "" {
			writeError(w, http.StatusBadRequest, code)
			return
		}
		hash, err := secure.HashPassword(in.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		u.PasswordHash = hash
	}
	if err := s.store.CreateUser(u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "username_taken")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.audit(r, a.user, "user_create", u.Username, true, "role="+u.Role)
	writeJSON(w, http.StatusCreated, toUserDTO(u))
}

// loadTargetUser parses the {id} path value and loads the user.
func (s *Server) loadTargetUser(w http.ResponseWriter, r *http.Request) *store.User {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found")
		return nil
	}
	u, err := s.store.GetUserByID(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return nil
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return nil
	}
	return u
}

// wouldRemoveLastAdmin reports whether demoting/disabling/deleting u leaves
// no active admin.
func (s *Server) wouldRemoveLastAdmin(u *store.User) (bool, error) {
	if !u.IsAdmin() || u.Disabled {
		return false, nil
	}
	n, err := s.store.CountActiveAdmins()
	return n <= 1, err
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request, a *authCtx) {
	u := s.loadTargetUser(w, r)
	if u == nil {
		return
	}
	var in struct {
		Role     *string `json:"role"`
		Email    *string `json:"email"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
		Unlock   bool    `json:"unlock"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	changes := []string{}
	killSessions := false

	removesAdmin := (in.Role != nil && *in.Role != store.RoleAdmin) || (in.Disabled != nil && *in.Disabled)
	if removesAdmin {
		if u.ID == a.user.ID {
			writeError(w, http.StatusBadRequest, "cannot_change_self")
			return
		}
		last, err := s.wouldRemoveLastAdmin(u)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		if last {
			writeError(w, http.StatusBadRequest, "last_admin")
			return
		}
	}
	if in.Role != nil && *in.Role != u.Role {
		if !validRole(*in.Role) {
			writeError(w, http.StatusBadRequest, "invalid_role")
			return
		}
		u.Role = *in.Role
		changes = append(changes, "role="+u.Role)
		killSessions = true
	}
	if in.Email != nil {
		email := strings.TrimSpace(*in.Email)
		if code := validateEmail(email); code != "" {
			writeError(w, http.StatusBadRequest, code)
			return
		}
		if inUse, err := s.emailInUse(email, u.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		} else if inUse {
			writeError(w, http.StatusConflict, "email_in_use")
			return
		}
		if !strings.EqualFold(email, u.Email) {
			// Changing the e-mail removes an existing OIDC link.
			u.OIDCSubject = ""
			changes = append(changes, "email")
		}
		u.Email = email
	}
	if in.Disabled != nil && *in.Disabled != u.Disabled {
		u.Disabled = *in.Disabled
		changes = append(changes, "disabled="+strconv.FormatBool(u.Disabled))
		killSessions = killSessions || u.Disabled
	}
	if in.Password != nil && *in.Password != "" {
		if code := validatePassword(*in.Password); code != "" {
			writeError(w, http.StatusBadRequest, code)
			return
		}
		hash, err := secure.HashPassword(*in.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		u.PasswordHash = hash
		changes = append(changes, "password")
		killSessions = true
	}
	if in.Unlock {
		u.LockedUntil = 0
		u.FailedLogins = 0
		changes = append(changes, "unlocked")
	}
	if err := s.store.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if killSessions {
		except := ""
		if u.ID == a.user.ID {
			except = a.sess.IDHash
		}
		_ = s.store.DeleteUserSessions(u.ID, except)
	}
	s.audit(r, a.user, "user_update", u.Username, true, strings.Join(changes, ", "))
	writeJSON(w, http.StatusOK, toUserDTO(u))
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request, a *authCtx) {
	u := s.loadTargetUser(w, r)
	if u == nil {
		return
	}
	if u.ID == a.user.ID {
		writeError(w, http.StatusBadRequest, "cannot_change_self")
		return
	}
	if last, err := s.wouldRemoveLastAdmin(u); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	} else if last {
		writeError(w, http.StatusBadRequest, "last_admin")
		return
	}
	if err := s.store.DeleteUser(u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.audit(r, a.user, "user_delete", u.Username, true, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleResetUserMFA(w http.ResponseWriter, r *http.Request, a *authCtx) {
	u := s.loadTargetUser(w, r)
	if u == nil {
		return
	}
	u.TOTPEnabled = false
	u.TOTPSecret = ""
	u.TOTPPending = ""
	if err := s.store.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.audit(r, a.user, "user_reset_mfa", u.Username, true, "")
	writeJSON(w, http.StatusOK, toUserDTO(u))
}

func (s *Server) handleUnlinkOIDC(w http.ResponseWriter, r *http.Request, a *authCtx) {
	u := s.loadTargetUser(w, r)
	if u == nil {
		return
	}
	u.OIDCSubject = ""
	if err := s.store.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.audit(r, a.user, "user_unlink_oidc", u.Username, true, "")
	writeJSON(w, http.StatusOK, toUserDTO(u))
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request, a *authCtx) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	entries, total, err := s.store.ListAudit(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "total": total})
}

func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request, a *authCtx) {
	res, err := s.store.VerifyAudit()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, res)
}
