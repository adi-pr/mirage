package session

import "time"

// Entry is one inbound SYN: when it arrived and which port it hit.
type Entry struct {
	Time time.Time
	Port uint16
}

// Timeline stores entries in chronological order, oldest first.
type Timeline []Entry

// Add appends e to the timeline, keeping only entries within window
// of e.Time and at most limit entries. The new entry's Time is used as
// "now". Entries must be added in chronological order; if e.Time is
// earlier than the timeline's last entry, Add ignores e.
func (t *Timeline) Add(e Entry, window time.Duration, limit int) bool {
	if len(*t) > 0 && e.Time.Before((*t)[len(*t)-1].Time) {
		return false
	}

	*t = append(*t, e)
	cutoff := e.Time.Add(-window)

	for len(*t) > 0 && !(*t)[0].Time.After(cutoff) {
		*t = (*t)[1:]
	}

	for len(*t) > limit {
		*t = (*t)[1:]
	}

	return true
}
