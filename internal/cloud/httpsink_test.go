package cloud

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"agentguard/internal/types"
)

// TestHTTPSinkRoundTrip ships an event through a Shipper configured with an
// "https" sink pointed at an httptest server, and asserts the server received
// the redacted event (with the bearer token) — the data-plane path end to end.
func TestHTTPSinkRoundTrip(t *testing.T) {
	var (
		mu      sync.Mutex
		got     []types.CloudEvent
		gotAuth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev types.CloudEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		got = append(got, ev)
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &types.CloudConfig{
		Enabled: true,
		Sinks: []types.CloudSink{{
			Name:            "preview",
			Type:            "https",
			Endpoint:        srv.URL,
			EnrollmentToken: "test-token",
		}},
	}
	s, err := NewShipper(cfg, nil)
	if err != nil {
		t.Fatalf("NewShipper: %v", err)
	}
	if s == nil {
		t.Fatal("expected an enabled shipper, got nil")
	}

	s.Ship(types.CloudEvent{EventID: "x1", Tool: "Bash", Decision: types.Deny, Rule: "egress.unapproved"})
	s.Close() // drains and closes

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("server got %d events, want 1", len(got))
	}
	if got[0].EventID != "x1" || got[0].Rule != "egress.unapproved" {
		t.Fatalf("unexpected event: %+v", got[0])
	}
	if gotAuth != "Bearer test-token" {
		t.Fatalf("Authorization=%q, want %q", gotAuth, "Bearer test-token")
	}
}

// TestHTTPSinkEndpointRequired confirms a misconfigured https sink (no endpoint)
// is a hard config error, not a silent no-op.
func TestHTTPSinkEndpointRequired(t *testing.T) {
	cfg := &types.CloudConfig{
		Enabled: true,
		Sinks:   []types.CloudSink{{Name: "broken", Type: "https"}},
	}
	if _, err := NewShipper(cfg, nil); err == nil {
		t.Fatal("expected error for https sink without endpoint")
	}
}

// TestHTTPSinkRetries verifies Write retries on a transient non-2xx and then
// succeeds, exercising the best-effort retry loop.
func TestHTTPSinkRetries(t *testing.T) {
	var calls int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError) // fail once
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewHTTPSink("preview", srv.URL, "")
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	start := time.Now()
	if err := sink.Write(types.CloudEvent{EventID: "r1"}); err != nil {
		t.Fatalf("Write after retry: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls < 2 {
		t.Fatalf("expected at least 2 attempts, got %d", calls)
	}
	if time.Since(start) < httpRetryBase {
		t.Fatalf("expected a backoff sleep before retry")
	}
}
