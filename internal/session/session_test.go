package session

import (
	"net/netip"
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
	m := NewManager(5*time.Minute, 100)

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
	m := NewManager(5*time.Minute, 100)

	m.Observe(inbound("203.0.113.5", 8000, t0.Add(time.Duration(1)*time.Second)))
	m.Observe(inbound("243.7.134.15", 3000, t0.Add(time.Duration(2)*time.Second)))

	if got := len(m.Snapshot()); got != 2 {
		t.Errorf("got %d sessions, want 2", got)
	}
}

// 3. An outbound event -> Ignored, and no session exists.
func TestObserveIgnoresOutbound(t *testing.T) {
	m := NewManager(5*time.Minute, 100)

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
	m := NewManager(5*time.Minute, 100)

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
	m := NewManager(time.Minute, 100)

	m.Observe(inbound("203.0.113.5", 8000, t0))

	expSessions := m.Expire(t0.Add(time.Minute))

	if got := len(expSessions); got != 1 {
		t.Errorf("got %d expired session, want 1", got)
	}
	if got := len(m.Snapshot()); got != 0 {
		t.Errorf("got %d session, want 0", got)
	}
}

// 6. The same host after expiry -> Created again, with a different ID.
func TestNewSessionAfterExpiry(t *testing.T) {
	m := NewManager(time.Minute, 100)

	_, oldID := m.Observe(inbound("203.0.113.5", 8000, t0))

	expired := m.Expire(t0.Add(2 * time.Minute))
	if len(expired) != 1 {
		t.Errorf("Expire() returned %d sessions, want 1", len(expired))
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
	m := NewManager(time.Minute, 1)

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
	m := NewManager(time.Minute, 100)

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
