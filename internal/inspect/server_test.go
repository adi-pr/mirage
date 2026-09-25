package inspect

import (
	"io"
	"net/http"
	"testing"
	"time"
)

func TestValidateListenAddr(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
	}{
		{addr: "127.0.0.1:8787", wantErr: false},
		{addr: "0.0.0.0:8787", wantErr: true},
		{addr: "[::1]:8787", wantErr: false},
		{addr: "192.168.1.10:8787", wantErr: true},
		{addr: "localhost:8787", wantErr: true},
		{addr: "127.0.0.1", wantErr: true},
		{addr: ":8787", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			err := ValidateListenAddr(tt.addr)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Errorf("ValidateListenAddr(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}

// TestHealthz starts a real server on a free port, calls /healthz, and shuts it down.
func TestHealthz(t *testing.T) {
	// Port 0 asks the OS for any free port, so tests never collide.
	s, err := Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := s.Shutdown(time.Second); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	}()

	resp, err := http.Get("http://" + s.Addr() + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok\n" {
		t.Errorf("body = %q, want %q", body, "ok\n")
	}
}

// TestHealthzRejectsPost verifies that /healthz only accepts GET requests.
func TestHealthzRejectsPost(t *testing.T) {
	s, err := Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := s.Shutdown(time.Second); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	}()

	resp, err := http.Post("http://"+s.Addr()+"/healthz", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// TestStartPortInUse verifies that starting a second server on an occupied
// address returns an error.
func TestStartPortInUse(t *testing.T) {
	s, err := Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := s.Shutdown(time.Second); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	}()

	_, err = Start(s.Addr())
	if err == nil {
		t.Fatal("Start on an occupied port succeeded, want error")
	}
}
