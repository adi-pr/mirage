package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
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
	rec := get(t, noSessions, "/sessions")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if got, want := rec.Body.String(), "[]\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// 3. getSessions fails -> 503.
func TestListSessionsUnavailable(t *testing.T) {
	failing := func(ctx context.Context) ([]session.Session, error) {
		return nil, errors.New("no sessions for you")
	}

	rec := get(t, failing, "/sessions")

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503; body: %s", rec.Code, rec.Body)
	}
}

// 4. GET /sessions/{ip} returns the full session, with ports sorted by number
// and the timeline in recorded order.
func TestGetSession(t *testing.T) {
	s := scanner()
	s.Timeline = session.Timeline{
		{Time: t0, Port: 443},
		{Time: t0.Add(500 * time.Millisecond), Port: 22},
		{Time: t0.Add(time.Second), Port: 80},
		{Time: t0.Add(1500 * time.Millisecond), Port: 443},
	}

	rec := get(t, fixedSessions(s), "/sessions/203.0.113.5")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var got sessionDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v; body: %s", err, rec.Body)
	}
	if got.ID != 1 || got.RemoteIP != s.RemoteAddr {
		t.Errorf("got ID %d from %s, want ID 1 from %s", got.ID, got.RemoteIP, s.RemoteAddr)
	}
	if want := []portHits{{22, 1}, {80, 1}, {443, 2}}; !slices.Equal(got.Ports, want) {
		t.Errorf("ports = %v, want %v", got.Ports, want)
	}
	if want := []uint16{443, 22, 80}; !slices.Equal(got.PortOrder, want) {
		t.Errorf("port_order = %v, want %v", got.PortOrder, want)
	}
	if want := []netip.Addr{netip.MustParseAddr("192.168.1.10")}; !slices.Equal(got.LocalAddrs, want) {
		t.Errorf("local_addrs = %v, want %v", got.LocalAddrs, want)
	}

	if len(got.Timeline) != len(s.Timeline) {
		t.Fatalf("got %d timeline entries, want %d", len(got.Timeline), len(s.Timeline))
	}
	for i, want := range s.Timeline {
		if e := got.Timeline[i]; !e.Time.Equal(want.Time) || e.Port != want.Port {
			t.Errorf("timeline[%d] = %v, want %v", i, e, want)
		}
	}
}

// 5. Unknown IP -> 404.
func TestGetSessionNotFound(t *testing.T) {
	rec := get(t, fixedSessions(scanner()), "/sessions/198.51.100.99")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body: %s", rec.Code, rec.Body)
	}
}

// 6. Not an IP -> 400.
func TestGetSessionBadIP(t *testing.T) {
	rec := get(t, fixedSessions(scanner()), "/sessions/not-an-ip")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body)
	}
}
