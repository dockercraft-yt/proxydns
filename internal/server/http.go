package server

import (
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"strings"
)

// apiError is the JSON error body. Code is a stable identifier that the
// frontend translates; Detail is optional technical information.
type apiError struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string, detail ...string) {
	e := apiError{Error: code}
	if len(detail) > 0 {
		e.Detail = detail[0]
	}
	writeJSON(w, status, e)
}

// decodeJSON parses a JSON request body strictly. It writes an error response
// and returns false on failure.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_content_type")
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

// clientIP returns the client address. X-Forwarded-For is only honoured when
// explicitly configured; the right-most entry is the one added by the proxy.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if ip := net.ParseIP(strings.TrimSpace(parts[i])); ip != nil {
					return ip.String()
				}
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
