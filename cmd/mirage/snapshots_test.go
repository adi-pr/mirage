package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/adi-pr/mirage/internal/session"
)

// 1. runSessions (played here by a goroutine) answers -> the asker gets the sessions.
func TestSnapshotAnswered(t *testing.T) {
	requests := make(chan snapshotRequest)
	done := make(chan struct{})

	want := []session.Session{
		{ID: 1, RemoteAddr: netip.MustParseAddr("203.0.113.5")},
		{ID: 2, RemoteAddr: netip.MustParseAddr("198.51.100.7")},
	}

	// Fake owner: answer exactly one request, the way runSessions will.
	go func() {
		reply := <-requests
		reply <- want
	}()

	get := snapshotFunc(requests, done)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got, err := get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sessions, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID {
			t.Errorf("session %d: ID = %d, want %d", i, got[i].ID, want[i].ID)
		}
	}
}

// 2. Nobody answers and the context times out -> context.DeadlineExceeded, no hang.
func TestSnapshotContextTimeout(t *testing.T) {
	t.Skip("TODO: make requests and done, but start no owner goroutine. " +
		"Call get with context.WithTimeout(..., 50*time.Millisecond) and check " +
		"errors.Is(err, context.DeadlineExceeded)")
}

// 3. runSessions has already exited (done is closed) -> errSessionsStopped right away.
func TestSnapshotOwnerStopped(t *testing.T) {
	t.Skip("TODO: close(done) before calling get. Use context.Background() so only " +
		"done can end the wait, and check errors.Is(err, errSessionsStopped)")
}

// Keeps the errors import used until the tests above are written. Delete it then.
var _ = errors.Is
