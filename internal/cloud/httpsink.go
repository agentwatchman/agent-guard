package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"agentguard/internal/types"
)

// HTTPSink delivers redacted events to a remote ingest endpoint over HTTP(S).
// It implements Sink and is the data-plane sink: unlike FileSink (local only),
// this is what carries events OFF the machine to a control plane.
//
// Delivery is best-effort with a bounded per-attempt timeout and a few quick
// retries to ride out transient blips. It still NEVER blocks the hook path —
// the Shipper calls Write from its background goroutine, and overflow is shed
// upstream by the bounded queue. Durable on-disk replay with long backoff (so
// events survive the daemon being offline) is a later step; see
// docs/cloud-mvp.md §4.2 / §7.
type HTTPSink struct {
	name     string
	endpoint string
	token    string // optional bearer credential (enrollment/device token)
	client   *http.Client
}

const (
	httpSinkTimeout = 5 * time.Second        // per-attempt
	httpSinkRetries = 2                      // extra attempts after the first
	httpRetryBase   = 200 * time.Millisecond // linear backoff step between attempts
)

// NewHTTPSink builds an HTTP(S) sink. endpoint is required; token is sent as a
// Bearer credential when non-empty.
func NewHTTPSink(name, endpoint, token string) (*HTTPSink, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("https sink %q: endpoint is required", name)
	}
	if name == "" {
		name = "https"
	}
	return &HTTPSink{
		name:     name,
		endpoint: endpoint,
		token:    token,
		client:   &http.Client{Timeout: httpSinkTimeout},
	}, nil
}

func (h *HTTPSink) Name() string { return h.name }

// Write POSTs the event as JSON, retrying a couple of times on transient errors
// or non-2xx responses. Returns the last error so the Shipper can log it.
func (h *HTTPSink) Write(ev types.CloudEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt <= httpSinkRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * httpRetryBase)
		}
		if lastErr = h.post(b); lastErr == nil {
			return nil
		}
	}
	return lastErr
}

func (h *HTTPSink) post(body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), httpSinkTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // drain so the connection can be reused
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ingest %s returned HTTP %d", h.endpoint, resp.StatusCode)
	}
	return nil
}

func (h *HTTPSink) Close() error { return nil }
