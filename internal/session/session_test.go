package session

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/adi-pr/mirage/internal/event"
)

var (
	t0      = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	localIP = netip.MustParseAddr("192.168.1.10")
)

// inbound builds an inbound SYN from src to localIP on the given port.
func inbound(src string, port uint16, at time.Time) event.NetworkEvent {
	return event.NetworkEvent{
		Timestamp:  at,
		SourceIP:   netip.MustParseAddr(src),
		SourcePort: 40000,
		DestIP:     localIP,
		DestPort:   port,
		Protocol:   "tcp",
		TCPFlags:   event.FlagSYN,
		Direction:  event.DirectionInbound,
	}
}

// 1. Three events from one host on different ports -> one session, three ports.
func TestObserveGroupsByRemote(t *testing.T) {
	m := NewManager(Config{Timeout: 5 * time.Minute, MaxSessions: 100})

	for i, port := range []uint16{22, 80, 443} {
		m.Observe(inbound("203.0.113.5", port, t0.Add(time.Duration(i)*time.Second)))
	}

	snap := m.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d sessions, want 1", len(snap))
	}
	if got := len(snap[0].Ports); got != 3 {
		t.Errorf("got %d distinct ports, want 3", got)
	}
	if got := snap[0].EventCount; got != 3 {
		t.Errorf("got %d events, want 3", got)
	}
	if got := snap[0].Duration(); got != 2*time.Second {
		t.Errorf("got duration %v, want 2s", got)
	}
}

// 2. Events from two hosts -> two sessions.
func TestObserveSeparatesHosts(t *testing.T) {
	m := NewManager(Config{Timeout: 5 * time.Minute, MaxSessions: 100})

	m.Observe(inbound("203.0.113.5", 8000, t0.Add(time.Duration(1)*time.Second)))
	m.Observe(inbound("243.7.134.15", 3000, t0.Add(time.Duration(2)*time.Second)))

	if got := len(m.Snapshot()); got != 2 {
		t.Errorf("got %d sessions, want 2", got)
	}
}

// 3. An outbound event -> Ignored, and no session exists.
func TestObserveIgnoresOutbound(t *testing.T) {
	m := NewManager(Config{Timeout: 5 * time.Minute, MaxSessions: 100})

	ev := inbound("203.0.113.5", 8000, t0.Add(time.Duration(1)*time.Second))
	ev.Direction = event.DirectionOutbound

	if got, _ := m.Observe(ev); got != Ignored {
		t.Errorf("got %d Observe Respose, want Ignored", got)
	}
	if got := len(m.Snapshot()); got != 0 {
		t.Errorf("got %d sessions, want 0", got)
	}
}

// 4. The same port twice -> hit count 2, but still one distinct port.
func TestObserveCountsRepeatedPort(t *testing.T) {
	m := NewManager(Config{Timeout: 5 * time.Minute, MaxSessions: 100})

	for i := 0; i < 2; i++ {
		m.Observe(inbound("203.0.113.5", 22, t0.Add(time.Duration(i)*time.Second)))
	}

	snap := m.Snapshot()

	if len(snap) != 1 {
		t.Fatalf("got %d sessions, want 1", len(snap))
	}
	if got := len(snap[0].Ports); got != 1 {
		t.Errorf("got %d distinct ports, want 1", got)
	}
	if got := snap[0].Ports[22]; got != 2 {
		t.Errorf("port 22 got %d hits, want 2", got)
	}
	if got := len(snap[0].PortOrder); got != 1 {
		t.Errorf("got %d unique ports, want 1", got)
	}
}

// 5. Expire just before the timeout keeps the session; just after returns it.
func TestExpire(t *testing.T) {
	m := NewManager(Config{Timeout: time.Minute, MaxSessions: 100})

	m.Observe(inbound("203.0.113.5", 8000, t0))

	expSessions := m.Expire(t0.Add(time.Minute))

	if got := len(expSessions); got != 0 {
		t.Errorf("got %d expired sessions, want 0", got)
	}
	if got := len(m.Snapshot()); got != 1 {
		t.Errorf("got %d sessions, want 1", got)
	}

	expSessions = m.Expire(t0.Add(time.Minute + time.Second))

	if got := len(expSessions); got != 1 {
		t.Fatalf("got %d expired sessions, want 1", got)
	}
	if got := len(m.Snapshot()); got != 0 {
		t.Errorf("got %d sessions, want 0", got)
	}
}

// 6. The same host after expiry -> Created again, with a different ID.
func TestNewSessionAfterExpiry(t *testing.T) {
	m := NewManager(Config{Timeout: time.Minute, MaxSessions: 100})

	_, oldID := m.Observe(inbound("203.0.113.5", 8000, t0))

	expired := m.Expire(t0.Add(2 * time.Minute))
	if len(expired) != 1 {
		t.Fatalf("Expire() returned %d sessions, want 1", len(expired))
	}
	if expired[0].ID != oldID {
		t.Errorf("expired session ID = %d, want %d", expired[0].ID, oldID)
	}

	newRes, newID := m.Observe(inbound("203.0.113.5", 8000, t0))
	if newRes != Created {
		t.Errorf("second Observe() = %d, want Created", newRes)
	}
	if newID == oldID {
		t.Errorf("new session reused expired ID %d", newID)
	}
}

// 7. Cap reached -> new hosts Rejected and counted, existing sessions still Updated.
func TestSessionCap(t *testing.T) {
	m := NewManager(Config{Timeout: time.Minute, MaxSessions: 1})

	_, hostAID := m.Observe(
		inbound("203.0.113.5", 8000, t0.Add(1*time.Second)),
	)

	hostBRes, _ := m.Observe(
		inbound("203.0.13.5", 8000, t0.Add(1*time.Second)),
	)
	if hostBRes != Rejected {
		t.Errorf("Observe(hostB) = %d, want Rejected", hostBRes)
	}

	if got := m.Rejected(); got != 1 {
		t.Errorf("Rejected() = %d, want 1", got)
	}

	hostAUpRes, hostAUpID := m.Observe(
		inbound("203.0.113.5", 8000, t0.Add(1*time.Second)),
	)

	if hostAUpRes != Updated {
		t.Errorf("Observe(hostA) = %d, want Updated", hostAUpRes)
	}

	if hostAUpID != hostAID {
		t.Errorf("hostA ID changed: got %v, want %v", hostAUpID, hostAID)
	}
}

// 8. Modifying a Snapshot result doesn't change the manager.
func TestSnapshotIsCopy(t *testing.T) {
	m := NewManager(Config{Timeout: time.Minute, MaxSessions: 100})

	m.Observe(inbound("203.0.113.5", 8000, t0))

	snap := m.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("Snapshot() returned %d sessions, want 1", len(snap))
	}

	// Modify the snapshot.
	snap[0].Ports[9999] = 1

	// Take a fresh snapshot from the manager.
	snap2 := m.Snapshot()
	if len(snap2) != 1 {
		t.Fatalf("second Snapshot() returned %d sessions, want 1", len(snap2))
	}

	if _, ok := snap2[0].Ports[9999]; ok {
		t.Errorf("port 9999 was added to manager through Snapshot()")
	}
}

// 9. CloseAll, Expire and Snapshot return sessions in ID order, every time.
func TestSessionsSortedByID(t *testing.T) {
	hosts := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5"}

	// Map order is random, so repeat to make an unsorted result show up.
	for range 20 {
		m := NewManager(Config{Timeout: time.Minute, MaxSessions: 100})
		for _, h := range hosts {
			m.Observe(inbound(h, 80, t0))
		}

		checkOrder(t, "Snapshot", m.Snapshot(), len(hosts))
		checkOrder(t, "Expire", m.Expire(t0.Add(2*time.Minute)), len(hosts))

		for _, h := range hosts {
			m.Observe(inbound(h, 80, t0))
		}
		checkOrder(t, "CloseAll", m.CloseAll(), len(hosts))
	}
}

func checkOrder(t *testing.T, name string, got []Session, want int) {
	t.Helper()
	if len(got) != want {
		t.Fatalf("%s returned %d sessions, want %d", name, len(got), want)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].ID >= got[i].ID {
			t.Fatalf("%s not sorted by ID: %d before %d", name, got[i-1].ID, got[i].ID)
		}
	}
}

// 10. Observed event appears in session timeline
func TestObservedEventAppearsInSessionTimeline(t *testing.T) {
	var PORT uint16 = 8000

	m := NewManager(Config{Timeout: time.Minute, MaxSessions: 100})
	m.Observe(inbound("203.0.113.5", PORT, t0))

	snap := m.Snapshot()
	if got := len(snap); got != 1 {
		t.Fatalf("got %d sessions, want 1", got)
	}

	timeline := snap[0].Timeline

	if got := len(timeline); got != 1 {
		t.Fatalf("got %d timeline entries, want 1", got)
	}

	for _, e := range timeline {
		if e.Port != PORT {
			t.Errorf("got %d port, want %d", e.Port, PORT)
		}
	}
}

// 11. First event of a new session is in timeline
func TestFirstEventOfNewSessionIsInTimeline(t *testing.T) {
	m := NewManager(Config{})

	if res, _ := m.Observe(inbound("203.0.113.5", 22, t0)); res != Created {
		t.Fatalf("Observe = %v, want Created", res)
	}

	timeline := m.Snapshot()[0].Timeline
	if len(timeline) != 1 {
		t.Fatalf("got %d timeline entries, want 1", len(timeline))
	}
	if e := timeline[0]; !e.Time.Equal(t0) || e.Port != 22 {
		t.Errorf("entry = %v, want port 22 at %v", e, t0)
	}
}

// 12. Modifying a snapshot's timeline doesn't change the manager's.
func TestSnapshotTimelineIsCopy(t *testing.T) {
	m := NewManager(Config{})
	m.Observe(inbound("203.0.113.5", 22, t0))

	snap := m.Snapshot()
	if len(snap) != 1 || len(snap[0].Timeline) != 1 {
		t.Errorf("got %d entries, want 1", len(snap))
	}

	snap[0].Timeline[0].Port = 9999

	snap = m.Snapshot()
	if got := snap[0].Timeline[0].Port; got != 22 {
		t.Errorf("got %d port, want 22", got)
	}
}

// timelinePorts returns the ports in the only session's timeline, oldest first.
func timelinePorts(t *testing.T, m *Manager) []uint16 {
	t.Helper()
	snap := m.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d sessions, want 1", len(snap))
	}
	var ports []uint16
	for _, e := range snap[0].Timeline {
		ports = append(ports, e.Port)
	}
	return ports
}

// 13. The configured limit caps the timeline, dropping the oldest entries.
func TestManagerAppliesWindowLimit(t *testing.T) {
	m := NewManager(Config{TimelineLimit: 2})
	for i := range 5 {
		m.Observe(inbound("203.0.113.5", uint16(i+1), t0.Add(time.Duration(i)*time.Second)))
	}

	if got, want := timelinePorts(t, m), []uint16{4, 5}; !slices.Equal(got, want) {
		t.Errorf("timeline ports = %v, want %v", got, want)
	}
}

// 14. The configured window drops entries that are too old.
func TestManagerUsesConfiguredTimelineWindow(t *testing.T) {
	m := NewManager(Config{TimelineWindow: time.Second})
	m.Observe(inbound("203.0.113.5", 1, t0))
	m.Observe(inbound("203.0.113.5", 2, t0.Add(600*time.Millisecond)))
	m.Observe(inbound("203.0.113.5", 3, t0.Add(1500*time.Millisecond)))

	// Port 1 is 1500ms old by now, so only it is dropped.
	if got, want := timelinePorts(t, m), []uint16{2, 3}; !slices.Equal(got, want) {
		t.Errorf("timeline ports = %v, want %v", got, want)
	}
}

// 15. Zero Config fields get their defaults.
func TestNewManagerFillsDefaults(t *testing.T) {
	m := NewManager(Config{})

	if m.timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", m.timeout, DefaultTimeout)
	}
	if m.maxSessions != DefaultMaxSessions {
		t.Errorf("maxSessions = %d, want %d", m.maxSessions, DefaultMaxSessions)
	}
	if m.timelineWindow != DefaultWindow {
		t.Errorf("timelineWindow = %v, want %v", m.timelineWindow, DefaultWindow)
	}
	if m.timelineLimit != DefaultLimit {
		t.Errorf("timelineLimit = %d, want %d", m.timelineLimit, DefaultLimit)
	}
}
