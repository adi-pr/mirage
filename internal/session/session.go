// Package session groups inbound connection events into per-remote-host sessions.
package session

import (
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/adi-pr/mirage/internal/event"
)

// Session is everything seen from one remote host within an idle timeout.
type Session struct {
	ID         uint64
	RemoteAddr netip.Addr
	FirstSeen  time.Time
	LastSeen   time.Time
	EventCount int
	Ports      map[uint16]int          // destination port -> hit count
	PortOrder  []uint16                // distinct ports in first-touch order
	LocalAddrs map[netip.Addr]struct{} // local addresses this host contacted
}

// Duration is the time between the first and last event of the session.
func (s *Session) Duration() time.Duration {
	return s.LastSeen.Sub(s.FirstSeen)
}

// clone returns a deep copy, so callers can't modify the manager's state.
func (s *Session) clone() Session {
	c := *s // copies the plain fields; the maps and slice are still shared

	c.Ports = maps.Clone(s.Ports)
	c.PortOrder = slices.Clone(s.PortOrder)
	c.LocalAddrs = maps.Clone(s.LocalAddrs)

	return c
}

// ObserveResult says what Observe did with an event.
type ObserveResult uint8

const (
	Ignored  ObserveResult = iota // not inbound, no session involved
	Created                       // started a new session
	Updated                       // added to an existing session
	Rejected                      // new host, but the session cap is reached
)

// Manager tracks active sessions. It is not safe for concurrent use:
// a single goroutine must own it.
type Manager struct {
	timeout     time.Duration
	maxSessions int
	nextID      uint64
	sessions    map[netip.Addr]*Session
	rejected    int
}

func NewManager(timeout time.Duration, maxSessions int) *Manager {
	return &Manager{
		timeout:     timeout,
		maxSessions: maxSessions,
		nextID:      1,
		sessions:    make(map[netip.Addr]*Session),
	}
}

// Observe adds an event to its remote host's session, creating the session if needed.
// It returns what happened and the ID of the session involved (0 if none).
func (m *Manager) Observe(ev event.NetworkEvent) (ObserveResult, uint64) {
	if ev.Direction != event.DirectionInbound {
		return Ignored, 0
	}
	remote := ev.RemoteAddr()

	s, ok := m.sessions[remote]
	if !ok {
		if len(m.sessions) >= m.maxSessions {
			m.rejected++
			return Rejected, 0
		}
		session := &Session{
			ID:         m.nextID,
			RemoteAddr: remote,
			FirstSeen:  ev.Timestamp,
			Ports:      make(map[uint16]int),
			LocalAddrs: make(map[netip.Addr]struct{}),
		}

		m.nextID++
		m.sessions[remote] = session
		s = session
	}

	s.LastSeen = ev.Timestamp
	s.EventCount += 1

	if s.Ports[ev.DestPort] == 0 {
		s.PortOrder = append(s.PortOrder, ev.DestPort)
	}

	s.Ports[ev.DestPort]++
	s.LocalAddrs[ev.DestIP] = struct{}{}

	if !ok {
		return Created, s.ID
	}

	return Updated, s.ID
}

// Expire removes and returns sessions idle for longer than the timeout as of now.
func (m *Manager) Expire(now time.Time) []Session {
	var closed []Session
	for remote, s := range m.sessions {
		if now.Sub(s.LastSeen) > m.timeout {
			closed = append(closed, *s)
			delete(m.sessions, remote)
		}
	}
	return closed
}

// CloseAll removes and returns every active session. Used at shutdown.
func (m *Manager) CloseAll() []Session {
	var closed []Session
	for _, s := range m.sessions {
		closed = append(closed, *s)
	}

	m.sessions = make(map[netip.Addr]*Session)

	return closed
}

// Snapshot returns deep copies of all active sessions.
func (m *Manager) Snapshot() []Session {
	var out []Session
	for _, s := range m.sessions {
		out = append(out, s.clone())
	}
	return out
}

// Rejected returns how many new sessions were refused because of the cap.
func (m *Manager) Rejected() int {
	return m.rejected
}
