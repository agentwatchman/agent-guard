package cloud

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"agentguard/internal/types"
)

// TestFileSinkRoundTrip ships a couple of redacted events through a real
// FileSink and reads them back as NDJSON, proving the end-to-end M0 contract.
func TestFileSinkRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	cfg := &types.CloudConfig{
		Enabled: true,
		Sinks:   []types.CloudSink{{Name: "local", Type: "file", Path: path}},
	}
	s, err := NewShipper(cfg, nil)
	if err != nil {
		t.Fatalf("NewShipper: %v", err)
	}
	if s == nil {
		t.Fatal("expected an enabled shipper, got nil")
	}

	s.Ship(types.CloudEvent{EventID: "a", Tool: "Bash", Decision: types.Deny})
	s.Ship(types.CloudEvent{EventID: "b", Tool: "Prompt", Decision: types.Deny})
	s.Close() // drains the queue and closes the sink

	lines := readNDJSON(t, path)
	if len(lines) != 2 {
		t.Fatalf("got %d events, want 2", len(lines))
	}
	if lines[0].EventID != "a" || lines[1].EventID != "b" {
		t.Fatalf("unexpected order/content: %+v", lines)
	}
}

// TestShipperDisabled confirms shipping is fully off by default: a nil/disabled
// config yields a nil Shipper whose methods are safe no-ops.
func TestShipperDisabled(t *testing.T) {
	for _, cfg := range []*types.CloudConfig{nil, {Enabled: false}, {Enabled: true}} {
		s, err := NewShipper(cfg, nil)
		if err != nil {
			t.Fatalf("NewShipper(%+v): %v", cfg, err)
		}
		if s != nil {
			t.Fatalf("expected nil shipper for %+v", cfg)
		}
		// nil-safe: must not panic.
		s.Ship(types.CloudEvent{EventID: "x"})
		if got := s.Dropped(); got != 0 {
			t.Fatalf("nil shipper Dropped()=%d, want 0", got)
		}
		s.Close()
	}
}

// TestShipperDropsOnOverflow proves backpressure never blocks the hook path:
// once the bounded queue is full, extra events are shed and counted instead of
// stalling Ship.
func TestShipperDropsOnOverflow(t *testing.T) {
	s := &Shipper{
		sinks: nil,
		ch:    make(chan types.CloudEvent, 1), // tiny queue, no drainer goroutine
		log:   nil,
	}
	// Fill the single slot, then overflow many times. With no consumer running,
	// every Ship after the first must be dropped (and never block).
	for i := 0; i < 50; i++ {
		s.Ship(types.CloudEvent{EventID: "e"})
	}
	if got := s.Dropped(); got != 49 {
		t.Fatalf("Dropped()=%d, want 49", got)
	}
}

func readNDJSON(t *testing.T, path string) []types.CloudEvent {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	var out []types.CloudEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev types.CloudEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("unmarshal %q: %v", sc.Text(), err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}
