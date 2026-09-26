// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Package metrics is the signer's Prometheus surface, in the text exposition
// format and without a client library: a handful of counters and two gauges
// do not justify a dependency in the most privileged component.
//
// What they are for: once a workload's start depends on the signer (a pod
// certificate blocks its pod until issued), a signer that has stopped
// answering must page someone. `pending_oldest_seconds` is the number the
// alert reads; the counters say why.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Registry holds the values. The zero value is not usable; call New.
type Registry struct {
	mu            sync.Mutex
	issued        uint64
	denied        map[string]uint64
	writeErrors   uint64
	conflicts     uint64
	issueErrors   uint64
	pending       int
	oldestPending float64
	lastList      time.Time
}

// New returns an empty registry.
func New() *Registry { return &Registry{denied: map[string]uint64{}} }

func (r *Registry) Issued()     { r.mu.Lock(); r.issued++; r.mu.Unlock() }
func (r *Registry) WriteError() { r.mu.Lock(); r.writeErrors++; r.mu.Unlock() }

// WriteConflict counts a status write the API answered with 409: another
// replica answered the request first, or the object moved. Not an error -
// two replicas are meant to race for every request.
func (r *Registry) WriteConflict() { r.mu.Lock(); r.conflicts++; r.mu.Unlock() }
func (r *Registry) IssueError()    { r.mu.Lock(); r.issueErrors++; r.mu.Unlock() }
func (r *Registry) Denied(reason string) {
	r.mu.Lock()
	r.denied[reason]++
	r.mu.Unlock()
}

// Listed records a successful list: how many requests for this signer are
// still unanswered, and how long the oldest of them has waited.
func (r *Registry) Listed(now time.Time, pending int, oldest time.Duration) {
	r.mu.Lock()
	r.lastList, r.pending, r.oldestPending = now, pending, oldest.Seconds()
	r.mu.Unlock()
}

// LastList is when the signer last saw the API. /healthz uses it.
func (r *Registry) LastList() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastList
}

// Render writes the exposition format.
func (r *Registry) Render() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	counter := func(name, help string, v uint64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	gauge := func(name, help string, v float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, v)
	}
	counter("pod_cert_signer_issued_total", "Certificates written to a request's status.", r.issued)
	fmt.Fprintf(&b, "# HELP pod_cert_signer_denied_total Requests denied, by reason.\n# TYPE pod_cert_signer_denied_total counter\n")
	reasons := make([]string, 0, len(r.denied))
	for k := range r.denied {
		reasons = append(reasons, k)
	}
	sort.Strings(reasons)
	for _, k := range reasons {
		fmt.Fprintf(&b, "pod_cert_signer_denied_total{reason=%q} %d\n", k, r.denied[k])
	}
	counter("pod_cert_signer_status_write_errors_total", "Status writes the API refused or that failed, conflicts excluded.", r.writeErrors)
	counter("pod_cert_signer_status_write_conflicts_total", "Status writes that lost the race to another replica (409); the request was answered.", r.conflicts)
	counter("pod_cert_signer_issue_errors_total", "Transient failures before a status write (KMS, parsing).", r.issueErrors)
	gauge("pod_cert_signer_pending_requests", "Unanswered requests for this signer at the last list.", float64(r.pending))
	gauge("pod_cert_signer_pending_oldest_seconds", "Age of the oldest unanswered request at the last list.", r.oldestPending)
	if !r.lastList.IsZero() {
		gauge("pod_cert_signer_last_list_timestamp_seconds", "When the signer last listed requests successfully.", float64(r.lastList.Unix()))
	}
	return b.String()
}

// Handler serves /metrics and /healthz. Healthy means the API was listed
// within maxAge; a signer that cannot reach the API is not ready to answer
// anything, and its liveness probe says so.
func (r *Registry) Handler(now func() time.Time, maxAge time.Duration) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprint(w, r.Render())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		last := r.LastList()
		if last.IsZero() || now().Sub(last) > maxAge {
			http.Error(w, "no successful list within "+maxAge.String(), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	return mux
}
