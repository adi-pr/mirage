package inspect

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/adi-pr/mirage/internal/session"
)

// sessionSummary is one row of GET /sessions.
type sessionSummary struct {
	ID            uint64     `json:"id"`
	RemoteIP      netip.Addr `json:"remote_ip"`
	FirstSeen     time.Time  `json:"first_seen"`
	LastSeen      time.Time  `json:"last_seen"`
	DurationMS    int64      `json:"duration_ms"`
	Events        int        `json:"events"`
	DistinctPorts int        `json:"distinct_ports"`
}

// portHits is one destination port and how many SYNs it received.
type portHits struct {
	Port uint16 `json:"port"`
	Hits int    `json:"hits"`
}

// sessionDetail is the body of GET /sessions/{ip}. Embedding sessionSummary
// puts its fields at the top level of the JSON object, next to the extra ones.
type sessionDetail struct {
	sessionSummary
	Ports      []portHits   `json:"ports"`       // sorted by port number
	PortOrder  []uint16     `json:"port_order"`  // first-touch order, as recorded
	LocalAddrs []netip.Addr `json:"local_addrs"` // sorted
}

// toSummary converts a session into its API summary.
func toSummary(s session.Session) sessionSummary {
	return sessionSummary{
		ID:            s.ID,
		RemoteIP:      s.RemoteAddr,
		FirstSeen:     s.FirstSeen,
		LastSeen:      s.LastSeen,
		DurationMS:    s.Duration().Milliseconds(),
		Events:        s.EventCount,
		DistinctPorts: len(s.Ports),
	}
}

// toDetail converts a session into its full API view.
func toDetail(s session.Session) sessionDetail {
	d := sessionDetail{
		sessionSummary: toSummary(s),
		PortOrder:      s.PortOrder,
	}

	d.Ports = make([]portHits, 0, len(s.Ports))
	for ports, hits := range s.Ports {
		d.Ports = append(d.Ports, portHits{
			Port: ports,
			Hits: hits,
		})
	}

	slices.SortFunc(d.Ports, func(a, b portHits) int {
		return cmp.Compare(a.Port, b.Port)
	})

	d.LocalAddrs = slices.Collect(maps.Keys(s.LocalAddrs))
	slices.SortFunc(d.LocalAddrs, func(a, b netip.Addr) int {
		return a.Compare(b)
	})

	return d
}
