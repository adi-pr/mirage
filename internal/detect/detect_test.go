package detect

import (
	"slices"
	"testing"
	"time"

	"github.com/adi-pr/mirage/internal/session"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// ports builds a timeline with one entry per port, all at time at.
func ports(at time.Time, ps ...uint16) session.Timeline {
	var tl session.Timeline
	for _, p := range ps {
		tl = append(tl, session.Entry{Time: at, Port: p})
	}
	return tl
}

// portRange builds a timeline hitting ports 1..n, all at time at.
func portRange(at time.Time, n int) session.Timeline {
	var tl session.Timeline
	for p := 1; p <= n; p++ {
		tl = append(tl, session.Entry{Time: at, Port: uint16(p)})
	}
	return tl
}

func TestPortBreadth(t *testing.T) {
	cfg := Config{PortBreadthWindow: 60 * time.Second, PortBreadthBaseline: 5, PortBreadthMax: 100}
	now := t0

	tests := []struct {
		name     string
		timeline session.Timeline
		want     int // expected Points
	}{
		{"empty timeline", nil, 0},
		{"at baseline", portRange(now, 5), 0},
		{"one above baseline", portRange(now, 6), 1},
		{"below baseline", portRange(now, 3), 0},
		{"same port 50 times", ports(now, slices.Repeat([]uint16{22}, 50)...), 0},
		{"exactly at max", portRange(now, 105), 100},
		{"above max", portRange(now, 200), 100},
		{"entries 61s old only", portRange(now.Add(-61*time.Second), 20), 0},
		{"entries exactly 60s old", portRange(now.Add(-60*time.Second), 20), 0},
		{"entries 59s old", portRange(now.Add(-59*time.Second), 6), 1},
		{"mix: 10 old ports (61s) + 6 recent ports", append(
			portRange(now.Add(-61*time.Second), 10), ports(now, 100, 101, 102, 103, 104, 105)...,
		), 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PortBreadth(tt.timeline, now, cfg)
			if got.Points != tt.want {
				t.Errorf("Points = %d, want %d", got.Points, tt.want)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.PortBreadthWindow != 60*time.Second {
		t.Errorf("expected PortBreadthWindow to be 60s, got %v", config.PortBreadthWindow)
	}

	if config.PortBreadthBaseline != 5 {
		t.Errorf("expected PortBreadthBaseline to be 5, got %d", config.PortBreadthBaseline)
	}

	if config.PortBreadthMax != 100 {
		t.Errorf("expected PortBreadthMax to be 100, got %d", config.PortBreadthMax)
	}
}
