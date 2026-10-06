// Package detect scores session behavior with deterministic rules.
package detect

import (
	"fmt"
	"time"

	"github.com/adi-pr/mirage/internal/session"
)

// Config holds the thresholds for every rule.
type Config struct {
	PortBreadthWindow   time.Duration // how far back R1 looks
	PortBreadthBaseline int           // distinct ports allowed before R1 scores
	PortBreadthMax      int           // most points R1 can give
}

// DefaultConfig returns the thresholds from docs/phase2.md.
func DefaultConfig() Config {
	return Config{
		PortBreadthWindow:   60 * time.Second,
		PortBreadthBaseline: 5,
		PortBreadthMax:      100,
	}
}

// Result is what one rule found.
type Result struct {
	Rule   string // which rule produced this, e.g. "port_breadth"
	Points int    // points this rule adds to the score
	Detail string // human-readable reason, e.g. "42 distinct ports in 60s"
}

// PortBreadth (R1) counts distinct destination ports among timeline entries
// Points are the count minus the baseline,
// at least 0 and at most the max.
func PortBreadth(timeline session.Timeline, now time.Time, cfg Config) Result {
	cutoff := now.Add(-cfg.PortBreadthWindow)

	distinctPorts := make(map[uint16]struct{})

	for _, e := range timeline {
		if !e.Time.After(cutoff) {
			continue
		}

		distinctPorts[e.Port] = struct{}{}
	}

	count := len(distinctPorts)

	points := min(max(count-cfg.PortBreadthBaseline, 0), cfg.PortBreadthMax)

	return Result{
		Rule:   "port_breadth",
		Points: points,
		Detail: fmt.Sprintf("%d distinct ports in %s", count, cfg.PortBreadthWindow),
	}
}
