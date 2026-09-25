// Package inspect serves a local, read-only HTTP API for looking at MIRAGE while it runs.
package inspect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// Server is the local inspection HTTP server.
type Server struct {
	srv      *http.Server
	listener net.Listener
	done     chan struct{} // closed when the serving goroutine has returned
}

// ValidateListenAddr returns an error unless addr is "ip:port" with a loopback IP,
// such as "127.0.0.1:8787" or "[::1]:8787". Session data shows who is scanning
// this host, so it must never be served on a public interface.
func ValidateListenAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}

	parse, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("example address usage: 127.0.0.1: %w", err)
	}
	if loopback := parse.IsLoopback(); !loopback {
		return fmt.Errorf("not a loopback address %q", addr)
	}

	return nil
}

// Start validates addr, binds it, and serves in a background goroutine.
// Binding happens here rather than in the goroutine, so errors like
// "address already in use" are returned to the caller.
func Start(addr string) (*Server, error) {
	if err := ValidateListenAddr(addr); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)

	var ln net.Listener
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}

	s := &Server{
		srv: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second, // don't let slow clients hold connections open
		},
		listener: ln,
		done:     make(chan struct{}),
	}

	go s.serve()
	return s, nil
}

// serve runs until Shutdown is called.
func (s *Server) serve() {
	defer close(s.done)

	err := s.srv.Serve(s.listener)

	if shutdown := errors.Is(err, http.ErrServerClosed); !shutdown {
		slog.Error("serve_error", "err", err)
	}
}

// Addr returns the address the server is actually listening on.
// Useful when listening on port 0, which picks a free port.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Shutdown stops accepting connections, waits up to timeout for in-flight
// requests to finish, and waits for the serving goroutine to return.
func (s *Server) Shutdown(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err := s.srv.Shutdown(ctx)
	<-s.done

	return err
}
