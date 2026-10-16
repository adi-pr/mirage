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

	if config.ConnectionRateWindow != time.Second {
		t.Errorf("expected ConnectionRateWindow to be 1s, got %v", config.ConnectionRateWindow)
	}

	if config.ConnectionRateBaseline != 10 {
		t.Errorf("expected ConnectionRateBaseline to be 10, got %d", config.ConnectionRateBaseline)
	}

	if config.ConnectionRateMax != 50 {
		t.Errorf("expected ConnectionRateMax to be 50, got %d", config.ConnectionRateMax)
	}
}

// burst builds a timeline hitting ports 1..n, one SYN every gap, starting at start.
func burst(start time.Time, n int, gap time.Duration) session.Timeline {
	var tl session.Timeline
	for i := range n {
		tl = append(tl, session.Entry{Time: start.Add(time.Duration(i) * gap), Port: uint16(i + 1)})
	}
	return tl
}

func TestConnectionRate(t *testing.T) {
	cfg := DefaultConfig() // window 1s, baseline 10, max 50
	now := t0

	tests := []struct {
		name     string
		timeline session.Timeline
		now      time.Time
		want     int // expected Points
	}{
		{"empty timeline", nil, now, 0},
		{"below baseline", portRange(now, 3), now, 0},
		{"at baseline", portRange(now, 10), now, 0},
		{"one above baseline", portRange(now, 11), now, 1},
		// R1 scores this 0 (one unique port); R2 counts every SYN.
		{"same port 50 times", ports(now, slices.Repeat([]uint16{22}, 50)...), now, 40},
		{"exactly at max", portRange(now, 60), now, 50},
		{"above max", portRange(now, 200), now, 50},
		{"entries 2s old", portRange(now.Add(-2*time.Second), 20), now, 0},
		{"entries exactly 1s old", portRange(now.Add(-time.Second), 20), now, 0},
		{"entries 999ms old", portRange(now.Add(-999*time.Millisecond), 20), now, 10},
		{"mix: 30 old (1.5s) + 15 recent", append(
			portRange(now.Add(-1500*time.Millisecond), 30), portRange(now, 15)...,
		), now, 5},
		// The genpcap scanner: one SYN every 10ms. docs/phase2.md says R2 = n - 10 at event n.
		{"scanner at event 18", burst(t0, 18, 10*time.Millisecond), t0.Add(170 * time.Millisecond), 8},
		{"scanner at event 28", burst(t0, 28, 10*time.Millisecond), t0.Add(270 * time.Millisecond), 18},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConnectionRate(tt.timeline, tt.now, cfg)
			if got.Points != tt.want {
				t.Errorf("Points = %d, want %d", got.Points, tt.want)
			}
			if got.Rule != "connection_rate" {
				t.Errorf("Rule = %q, want connection_rate", got.Rule)
			}
		})
	}
}

// ConnectionRate must use the config it is given, not the default numbers.
func TestConnectionRateUsesConfig(t *testing.T) {
	cfg := Config{ConnectionRateWindow: 500 * time.Millisecond, ConnectionRateBaseline: 2, ConnectionRateMax: 5}

	// SYNs at 0, 100, ..., 900ms. With now = 900ms the window (400ms, 900ms]
	// holds the 5 SYNs at 500..900ms: 5 - 2 = 3 points.
	if got := ConnectionRate(burst(t0, 10, 100*time.Millisecond), t0.Add(900*time.Millisecond), cfg); got.Points != 3 {
		t.Errorf("window 500ms, baseline 2: Points = %d, want 3", got.Points)
	}

	// 20 SYNs at now: 20 - 2 = 18, capped at 5.
	if got := ConnectionRate(portRange(t0, 20), t0, cfg); got.Points != 5 {
		t.Errorf("max 5: Points = %d, want 5", got.Points)
	}
}
