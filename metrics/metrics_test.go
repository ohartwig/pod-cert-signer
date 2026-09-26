// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

package metrics_test

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ohartwig/pod-cert-signer/metrics"
)

var t0 = time.Date(2026, 9, 26, 5, 0, 0, 0, time.UTC)

func TestRenderCarriesEveryValue(t *testing.T) {
	r := metrics.New()
	r.Issued()
	r.Issued()
	r.Denied("NoGrant")
	r.WriteError()
	r.WriteConflict()
	r.WriteConflict()
	r.Listed(t0, 3, 90*time.Second)
	out := r.Render()
	for _, want := range []string{
		"pod_cert_signer_issued_total 2",
		`pod_cert_signer_denied_total{reason="NoGrant"} 1`,
		"pod_cert_signer_status_write_errors_total 1",
		"pod_cert_signer_status_write_conflicts_total 2",
		"pod_cert_signer_pending_requests 3",
		"pod_cert_signer_pending_oldest_seconds 90",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

// /healthz is unhealthy until the first successful list, and again when the
// last one is older than maxAge: a signer that cannot reach the API answers
// nothing, and its liveness probe must say so.
func TestHealthzFollowsTheLastList(t *testing.T) {
	r := metrics.New()
	now := t0
	h := r.Handler(func() time.Time { return now }, time.Minute)
	code := func() int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
		_, _ = io.ReadAll(rec.Body)
		return rec.Code
	}
	if c := code(); c != 503 {
		t.Fatalf("before any list: %d, want 503", c)
	}
	r.Listed(t0, 0, 0)
	if c := code(); c != 200 {
		t.Fatalf("right after a list: %d, want 200", c)
	}
	now = t0.Add(2 * time.Minute)
	if c := code(); c != 503 {
		t.Fatalf("list two minutes old with maxAge 1m: %d, want 503", c)
	}
}
