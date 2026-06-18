package server

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"agentguard/internal/types"
)

// metrics holds lightweight, lock-free counters for operational visibility,
// exposed as JSON at /metrics. They complement (don't replace) the audit log:
// the audit log is the per-event record; these are cheap running aggregates for
// "how much is being blocked?" without parsing the log.
type metrics struct {
	evalAllow atomic.Int64
	evalAsk   atomic.Int64
	evalDeny  atomic.Int64
	scanClean atomic.Int64
	scanDeny  atomic.Int64
}

func (m *metrics) recordEvaluate(decision string) {
	switch decision {
	case types.Allow:
		m.evalAllow.Add(1)
	case types.Ask:
		m.evalAsk.Add(1)
	case types.Deny:
		m.evalDeny.Add(1)
	}
}

func (m *metrics) recordScan(found bool) {
	if found {
		m.scanDeny.Add(1)
	} else {
		m.scanClean.Add(1)
	}
}

func (m *metrics) snapshot() map[string]int64 {
	ea, ek, ed := m.evalAllow.Load(), m.evalAsk.Load(), m.evalDeny.Load()
	sc, sd := m.scanClean.Load(), m.scanDeny.Load()
	return map[string]int64{
		"evaluate_total": ea + ek + ed,
		"evaluate_allow": ea,
		"evaluate_ask":   ek,
		"evaluate_deny":  ed,
		"scan_total":     sc + sd,
		"scan_clean":     sc,
		"scan_deny":      sd,
	}
}

func (d *Daemon) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(d.met.snapshot())
}
