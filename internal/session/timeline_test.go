package session

import (
	"testing"
	"time"
)

func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

// 1. entries older than the window are dropped
func TestTimeline_DropsEntriesOlderThanWindow(t *testing.T) {
	var timeline Timeline

	timeline.Add(Entry{Time: at(0), Port: 80}, time.Minute, 10)
	timeline.Add(Entry{Time: at(30_000), Port: 81}, time.Minute, 10)
	timeline.Add(Entry{Time: at(60_001), Port: 82}, time.Minute, 10)

	if got := len(timeline); got != 2 {
		t.Fatalf("got %d entries, want 2", got)
	}

	if timeline[0].Port != 81 {
		t.Errorf("oldest entry has port %d, want 81", timeline[0].Port)
	}
}

// 2. Drops entry if exactly at window boundary
func TestTimeline_DropsEntryExactlyAtWindowBoundary(t *testing.T) {
	var timeline Timeline

	timeline.Add(Entry{Time: at(0), Port: 80}, 60*time.Second, 10)
	timeline.Add(Entry{Time: at(60_000), Port: 81}, 60*time.Second, 10)

	if got := len(timeline); got != 1 {
		t.Fatalf("got %d entries, want 1", got)
	}

	if timeline[0].Port != 81 {
		t.Errorf("oldest entry has port %d, want 81", timeline[0].Port)
	}
}

// 3. Limit Drops Oldest Entries first
func TestTimeline_LimitDropsOldestEntriesFirst(t *testing.T) {
	var timeline Timeline

	for i := 0; i < 5; i++ {
		timeline.Add(
			Entry{Time: at(i * 1000), Port: 80 + uint16(i)},
			time.Minute,
			3,
		)
	}

	if got := len(timeline); got != 3 {
		t.Fatalf("got %d entries, want 3", got)
	}

	wantPorts := []uint16{82, 83, 84}
	for i, want := range wantPorts {
		if got := timeline[i].Port; got != want {
			t.Fatalf("entry %d, has port %d, want %d", i, got, want)
		}
	}
}

func TestTimeline_HandlesEmptyTimeline(t *testing.T) {
	var timeline Timeline
	timeline.Add(Entry{Time: t0, Port: 80}, time.Minute, 10)

	if got := len(timeline); got != 1 {
		t.Fatalf("got %d entries, want 1", got)
	}
}

func TestTimeline_HandlesOutOfOrderEntries(t *testing.T) {
	var timeline Timeline

	ok := timeline.Add(Entry{Time: at(1000), Port: 80}, time.Minute, 10)
	if !ok {
		t.Fatal("failed to add entry")
	}

	ok = timeline.Add(Entry{Time: at(2000), Port: 81}, time.Minute, 10)
	if !ok {
		t.Fatal("failed to add entry")
	}

	ok = timeline.Add(Entry{Time: at(1500), Port: 82}, time.Minute, 10)
	if ok {
		t.Fatal("failed to add entry")
	}

	if got := len(timeline); got != 2 {
		t.Fatalf("got %d entries, want 2", got)
	}

	if timeline[0].Port != 80 || timeline[1].Port != 81 {
		t.Errorf("timeline changed after out-of-order entry: got %+v", timeline)
	}
}

func TestTimeline_KeepsEntriesWithEqualTimes(t *testing.T) {
	var timeline Timeline

	timeline.Add(Entry{Time: t0, Port: 80}, time.Minute, 10)
	timeline.Add(Entry{Time: t0, Port: 81}, time.Minute, 10)
	timeline.Add(Entry{Time: t0, Port: 82}, time.Minute, 10)

	if got := len(timeline); got != 3 {
		t.Fatalf("got %d entries, want 3", got)
	}

	for i, want := range []uint16{80, 81, 82} {
		if got := timeline[i].Port; got != want {
			t.Fatalf("entry %d has port %d, want %d", i, got, want)
		}
	}
}
func TestTimeline_WindowAndLimitTogether(t *testing.T) {
	var timeline Timeline

	const (
		window = time.Second
		limit  = 3
	)

	timeline.Add(Entry{Time: at(0), Port: 80}, window, limit)
	timeline.Add(Entry{Time: at(100), Port: 81}, window, limit)
	timeline.Add(Entry{Time: at(200), Port: 82}, window, limit)
	timeline.Add(Entry{Time: at(1150), Port: 83}, window, limit)

	if got := len(timeline); got != 2 {
		t.Fatalf("got %d entries, want 2", got)
	}

	wantPorts := []uint16{82, 83}
	for i, want := range wantPorts {
		if got := timeline[i].Port; got != want {
			t.Errorf("entry %d has port %d, want %d", i, got, want)
		}
	}
}
