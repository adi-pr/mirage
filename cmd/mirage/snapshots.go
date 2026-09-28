package main

import (
	"context"
	"errors"

	"github.com/adi-pr/mirage/internal/session"
)

// errSessionsStopped is returned when the session goroutine has already exited,
// so there is nobody left to answer a snapshot request.
var errSessionsStopped = errors.New("session tracking has stopped")

// snapshotRequest is a request for the current sessions: runSessions sends
// manager.Snapshot() back on it. It must have a buffer of 1, so runSessions
// never blocks on the reply, even if the asker has already given up.
type snapshotRequest chan []session.Session

// snapshotFunc returns a function that other goroutines (the HTTP handlers,
// from 6.3 on) call to get a copy of the live sessions. It never touches the
// manager itself: it asks runSessions over the requests channel and waits.
//
// done must be closed when runSessions returns.
func snapshotFunc(requests chan<- snapshotRequest, done <-chan struct{}) func(ctx context.Context) ([]session.Session, error) {
	return func(ctx context.Context) ([]session.Session, error) {
		reply := make(snapshotRequest, 1)

		select {
		case requests <- reply:
			// Request succcessfully sent
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
			return nil, errSessionsStopped
		}

		select {
		case sessions := <-reply:
			return sessions, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
			return nil, errSessionsStopped
		}
	}
}
