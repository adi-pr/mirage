package inspect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/adi-pr/mirage/internal/session"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// noSessions is a SessionsFunc that reports no active sessions.
func noSessions(ctx context.Context) ([]session.Session, error) {
	return nil, nil
}

// fixedSessions returns a SessionsFunc that always reports the given sessions.
func fixedSessions(sessions ...session.Session) SessionsFunc {
	return func(ctx context.Context) ([]session.Session, error) {
		return sessions, nil
	}
}

// scanner is a sample session: one host that hit three ports, 443 twice.
func scanner() session.Session {
	return session.Session{
		ID:         1,
		RemoteAddr: netip.MustParseAddr("203.0.113.5"),
		FirstSeen:  t0,
		LastSeen:   t0.Add(1500 * time.Millisecond),
		EventCount: 4,
		Ports:      map[uint16]int{443: 2, 22: 1, 80: 1},
		PortOrder:  []uint16{443, 22, 80},
		LocalAddrs: map[netip.Addr]struct{}{netip.MustParseAddr("192.168.1.10"): {}},
	}
}

// get sends a GET request through the router and returns the recorded response.
// httptest.NewRecorder captures what the handler writes; no real port is opened.
func get(t *testing.T, getSessions SessionsFunc, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	newMux(getSessions).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// 1. GET /sessions lists every session as a summary.
func TestListSessions(t *testing.T) {
	other := scanner()
	other.ID = 2
	other.RemoteAddr = netip.MustParseAddr("198.51.100.7")

	rec := get(t, fixedSessions(scanner(), other), "/sessions")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var got []sessionSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v; body: %s", err, rec.Body)
	}
	if len(got) != 2 {
		t.Fatalf("got %d sessions, want 2", len(got))
	}
	if got[0].ID != 1 || got[0].RemoteIP.String() != "203.0.113.5" {
		t.Errorf("first session = %+v, want ID 1 from 203.0.113.5", got[0])
	}
	if got[0].DistinctPorts != 3 {
		t.Errorf("distinct_ports = %d, want 3", got[0].DistinctPorts)
	}
	if got[0].DurationMS != 1500 {
		t.Errorf("duration_ms = %d, want 1500", got[0].DurationMS)
	}
}

// 2. No sessions -> 200 with an empty JSON list "[]", not "null".
func TestListSessionsEmpty(t *testing.T) {
	t.Skip("TODO: get(t, noSessions, \"/sessions\"); check the status is 200 and " +
		"rec.Body.String() is \"[]\\n\" (the encoder adds a newline)")
}

// 3. getSessions fails -> 503.
func TestListSessionsUnavailable(t *testing.T) {
	t.Skip("TODO: write a SessionsFunc that returns an error (errors.New), " +
		"call /sessions with it, and check for http.StatusServiceUnavailable")
}

// 4. GET /sessions/{ip} returns the full session, with ports sorted by number.
func TestGetSession(t *testing.T) {
	t.Skip("TODO: get(t, fixedSessions(scanner()), \"/sessions/203.0.113.5\"); " +
		"decode into sessionDetail; check Ports is [{22 1} {80 1} {443 2}] and " +
		"PortOrder is still [443 22 80]")
}

// 5. Unknown IP -> 404.
func TestGetSessionNotFound(t *testing.T) {
	t.Skip("TODO: ask for /sessions/198.51.100.99 with fixedSessions(scanner())")
}

// 6. Not an IP -> 400.
func TestGetSessionBadIP(t *testing.T) {
	t.Skip("TODO: ask for /sessions/not-an-ip")
}
