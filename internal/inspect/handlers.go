package inspect

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/adi-pr/mirage/internal/session"
)

// requestTimeout caps how long a handler waits for the session goroutine.
const requestTimeout = 2 * time.Second

// SessionsFunc returns a copy of the live sessions. In MIRAGE it asks the
// session goroutine; in tests it can simply return fixed data.
type SessionsFunc func(ctx context.Context) ([]session.Session, error)

// api holds what the handlers need.
type api struct {
	getSessions SessionsFunc
}

// newMux builds the router. It is separate from Start so tests can use it
// with httptest, without opening a real port.
func newMux(getSessions SessionsFunc) *http.ServeMux {
	a := &api{getSessions: getSessions}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /sessions", a.listSessions)
	mux.HandleFunc("GET /sessions/{ip}", a.getSession)
	return mux
}

// handleHealthz reports that the process is up. It returns 200 with "ok".
func handleHealthz(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "ok")
}

// sessions fetches live sessions with a timeout. On failure it writes a 503
// and returns ok=false, so handlers can simply return.
func (a *api) sessions(w http.ResponseWriter, r *http.Request) (sessions []session.Session, ok bool) {
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	sessions, err := a.getSessions(ctx)
	if err != nil {
		slog.Warn("inspect_sessions_unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "sessions unavailable")
		return nil, false
	}
	return sessions, true
}

// listSessions handles GET /sessions: a summary of every active session.
func (a *api) listSessions(w http.ResponseWriter, r *http.Request) {
	sessions, ok := a.sessions(w, r)
	if !ok {
		return
	}

	summaries := make([]sessionSummary, 0, len(sessions))
	for _, s := range sessions {
		summaries = append(summaries, toSummary(s))
	}

	writeJSON(w, http.StatusOK, summaries)
}

// getSession handles GET /sessions/{ip}: one session in full.
func (a *api) getSession(w http.ResponseWriter, r *http.Request) {
	targetAddr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("error parsing ip %q, %q", r.PathValue("ip"), err))
		return
	}
	targetAddr = targetAddr.Unmap()

	sessions, ok := a.sessions(w, r)
	if !ok {
		return
	}

	for _, s := range sessions {
		if s.RemoteAddr == targetAddr {
			writeJSON(w, http.StatusOK, toDetail(s))
			return
		}
	}

	writeError(w, http.StatusNotFound, fmt.Sprintf("no active session for %q", targetAddr))
}

// writeJSON sends v as a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Headers are already sent, so all we can do is log it.
		slog.Warn("inspect_write_failed", "error", err)
	}
}

// writeError sends {"error": msg} with the given status code.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
