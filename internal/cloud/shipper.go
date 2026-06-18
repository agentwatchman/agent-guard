package cloud

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"agentguard/internal/types"
)

// Sink is one destination for redacted events. Implementations must be safe for
// use by the single background shipper goroutine.
type Sink interface {
	Name() string
	Write(ev types.CloudEvent) error
	Close() error
}

// Shipper fans redacted events out to one or more sinks OFF the hook path. Ship
// is non-blocking: events go onto a bounded in-memory queue drained by a
// background goroutine, so a slow or broken sink can never stall a tool-call
// decision. On overflow the newest event is dropped and a counter is bumped
// (visibility over backpressure). All methods are nil-safe, so the daemon runs
// normally with shipping disabled (shipper == nil).
type Shipper struct {
	sinks   []Sink
	ch      chan types.CloudEvent
	wg      sync.WaitGroup
	dropped atomic.Int64
	log     *slog.Logger
}

// queueDepth is the in-memory buffer between the hook path and disk/network IO.
// Sized so normal bursts never drop; sustained overflow (a wedged sink) sheds
// the newest events rather than blocking enforcement.
const queueDepth = 1024

// NewShipper builds a Shipper from config. Returns (nil, nil) when cloud
// shipping is disabled or resolves to zero usable sinks — callers treat a nil
// Shipper as "off". A bad sink config (e.g. an unwritable file) is a real error.
func NewShipper(cfg *types.CloudConfig, log *slog.Logger) (*Shipper, error) {
	if cfg == nil || !cfg.Enabled || len(cfg.Sinks) == 0 {
		return nil, nil
	}
	if log == nil {
		log = slog.Default()
	}
	var sinks []Sink
	for _, sc := range cfg.Sinks {
		switch sc.Type {
		case "", "file":
			fsink, err := NewFileSink(sc.Name, sc.Path)
			if err != nil {
				return nil, fmt.Errorf("cloud sink %q: %w", sc.Name, err)
			}
			sinks = append(sinks, fsink)
		case "https", "http":
			hsink, err := NewHTTPSink(sc.Name, sc.Endpoint, sc.EnrollmentToken)
			if err != nil {
				return nil, fmt.Errorf("cloud sink %q: %w", sc.Name, err)
			}
			sinks = append(sinks, hsink)
		default:
			// Unknown sink type — skip with a warning rather than failing the
			// whole daemon over a not-yet-supported sink.
			log.Warn("skipping unsupported cloud sink type", "name", sc.Name, "type", sc.Type)
		}
	}
	if len(sinks) == 0 {
		return nil, nil
	}
	s := &Shipper{
		sinks: sinks,
		ch:    make(chan types.CloudEvent, queueDepth),
		log:   log,
	}
	s.wg.Add(1)
	go s.loop()
	return s, nil
}

// loop drains the queue and writes each event to every sink. One sink's failure
// doesn't stop the others (independent best-effort delivery).
func (s *Shipper) loop() {
	defer s.wg.Done()
	for ev := range s.ch {
		for _, sink := range s.sinks {
			if err := sink.Write(ev); err != nil {
				s.log.Warn("cloud sink write failed", "sink", sink.Name(), "err", err)
			}
		}
	}
}

// Ship enqueues a redacted event for delivery. Non-blocking and nil-safe: if the
// queue is full the event is dropped (counted) so the hook path never stalls.
func (s *Shipper) Ship(ev types.CloudEvent) {
	if s == nil {
		return
	}
	select {
	case s.ch <- ev:
	default:
		s.dropped.Add(1)
	}
}

// Dropped returns the number of events shed due to a full queue.
func (s *Shipper) Dropped() int64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

// Close stops accepting events, drains what's queued, and closes the sinks.
func (s *Shipper) Close() {
	if s == nil {
		return
	}
	close(s.ch)
	s.wg.Wait()
	for _, sink := range s.sinks {
		_ = sink.Close()
	}
	if n := s.dropped.Load(); n > 0 {
		s.log.Warn("cloud shipper dropped events on overflow", "dropped", n)
	}
}

// FileSink appends redacted events to a local NDJSON file (one JSON object per
// line). This is the M0 sink: it proves the end-to-end contract with zero infra
// and doubles as the offline buffer that an HTTPS sink (M1) will replay from.
type FileSink struct {
	name string
	mu   sync.Mutex
	fp   *os.File
}

// NewFileSink opens (creating/appending) the NDJSON file at path. An empty path
// defaults to ~/.agentguard/events.ndjson. The file is user-only (0600).
func NewFileSink(name, path string) (*FileSink, error) {
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".agentguard", "events.ndjson")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	fp, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = "file"
	}
	return &FileSink{name: name, fp: fp}, nil
}

func (f *FileSink) Name() string { return f.name }

func (f *FileSink) Write(ev types.CloudEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f.mu.Lock()
	defer f.mu.Unlock()
	_, err = f.fp.Write(b)
	return err
}

func (f *FileSink) Close() error { return f.fp.Close() }
