// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ohartwig/pod-cert-signer/ca"
	"github.com/ohartwig/pod-cert-signer/controller"
	"github.com/ohartwig/pod-cert-signer/fake/kubefake"
	"github.com/ohartwig/pod-cert-signer/issuer"
	"github.com/ohartwig/pod-cert-signer/kube"
	"github.com/ohartwig/pod-cert-signer/metrics"
	"github.com/ohartwig/pod-cert-signer/policy"
)

const signer = "koh.ole-hartwig.eu/workload"

const pol = `{
  "signerName": "koh.ole-hartwig.eu/workload",
  "trustDomain": "koh.ole-hartwig.eu",
  "dnsNamesAnnotation": "koh.ole-hartwig.eu/dns-names",
  "lifetime": "24h", "refreshAt": 0.66, "keyTypes": ["ECDSAP256"],
  "grants": [{"namespace": "kube-system", "serviceAccount": "traefik", "usage": "client", "ou": "crowdsec-agent"}]
}`

type rig struct {
	reg  *metrics.Registry
	srv  *kubefake.Server
	ca   *x509.Certificate
	stop func()
}

// start runs a controller against the fake API server. The resync is short
// so that a request whose first answer failed is retried within the test.
func start(t *testing.T, tweak func(*kubefake.Server)) *rig {
	t.Helper()
	srv := kubefake.New("t0ken")
	if tweak != nil {
		tweak(srv)
	}
	p, err := policy.Parse([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := ca.New(key, "test CA", p.TrustDomain, time.Now(), 24*365*time.Hour)
	caCert, _ := x509.ParseCertificate(der)
	reg := metrics.New()
	c := &controller.Controller{
		Metrics:    reg,
		API:        &kube.Client{Base: srv.URL, HTTP: srv.Client(), Token: "t0ken"},
		Issuer:     &issuer.Issuer{Policy: p, CA: issuer.CA{Cert: caCert, Signer: key}},
		SignerName: signer,
		Now:        time.Now,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Resync:     200 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()
	return &rig{reg: reg, srv: srv, ca: caCert, stop: func() { cancel(); <-done; srv.Close() }}
}

func request(t *testing.T, ns, name, sa, signerName string) map[string]any {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"apiVersion": "certificates.k8s.io/v1", "kind": "PodCertificateRequest",
		"metadata": map[string]any{"name": name, "namespace": ns, "generation": 1},
		"spec": map[string]any{
			"signerName": signerName, "podName": "p", "podUID": "u1",
			"serviceAccountName": sa, "serviceAccountUID": "u2", "nodeName": "n", "nodeUID": "u3",
			"maxExpirationSeconds": 86400,
			"stubPKCS10Request":    base64.StdEncoding.EncodeToString(csr),
		},
	}
}

// waitFor polls the fake until cond holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func conditions(o map[string]any) []map[string]any {
	st, _ := o["status"].(map[string]any)
	cs, _ := st["conditions"].([]any)
	out := make([]map[string]any, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.(map[string]any))
	}
	return out
}

func TestAGrantedRequestIsIssuedOnce(t *testing.T) {
	r := start(t, nil)
	defer r.stop()
	r.srv.Add(request(t, "kube-system", "req-1", "traefik", signer))

	waitFor(t, "Issued", func() bool { return len(conditions(r.srv.Get("kube-system", "req-1"))) > 0 })
	o := r.srv.Get("kube-system", "req-1")
	cs := conditions(o)
	if len(cs) != 1 || cs[0]["type"] != "Issued" {
		t.Fatalf("conditions %v", cs)
	}
	st := o["status"].(map[string]any)
	blk, _ := pem.Decode([]byte(st["certificateChain"].(string)))
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(r.ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("chain does not verify: %v", err)
	}
	for _, f := range []string{"notBefore", "notAfter", "beginRefreshAt"} {
		if st[f] == nil {
			t.Fatalf("status.%s missing", f)
		}
	}
	// The MODIFIED event of our own write, and every resync after it, must
	// not produce a second answer.
	time.Sleep(600 * time.Millisecond)
	if n := r.srv.Updates(); n != 1 {
		t.Fatalf("%d status writes, want exactly 1", n)
	}
}

func TestAnUngrantedRequestIsDeniedWithItsReason(t *testing.T) {
	r := start(t, nil)
	defer r.stop()
	r.srv.Add(request(t, "default", "req-2", "default", signer))
	waitFor(t, "Denied", func() bool { return len(conditions(r.srv.Get("default", "req-2"))) > 0 })
	o := r.srv.Get("default", "req-2")
	cs := conditions(o)
	if cs[0]["type"] != "Denied" || cs[0]["reason"] != string(issuer.ReasonNoGrant) {
		t.Fatalf("conditions %v", cs)
	}
	if o["status"].(map[string]any)["certificateChain"] != nil {
		t.Fatal("a denied request carries a certificate")
	}
}

func TestARequestForAnotherSignerIsLeftAlone(t *testing.T) {
	r := start(t, nil)
	defer r.stop()
	r.srv.Add(request(t, "kube-system", "req-3", "traefik", "example.com/other"))
	time.Sleep(600 * time.Millisecond)
	if n := r.srv.Updates(); n != 0 {
		t.Fatalf("%d status writes to a request for another signer", n)
	}
}

// A 409 on the first write leaves the request pending; the next list picks
// it up again and it is answered - once.
func TestAConflictIsRetriedByTheNextList(t *testing.T) {
	r := start(t, func(s *kubefake.Server) { s.ConflictNext = 1 })
	defer r.stop()
	r.srv.Add(request(t, "kube-system", "req-4", "traefik", signer))
	waitFor(t, "Issued after a conflict", func() bool { return len(conditions(r.srv.Get("kube-system", "req-4"))) > 0 })
	time.Sleep(400 * time.Millisecond)
	if n := r.srv.Updates(); n != 1 {
		t.Fatalf("%d accepted status writes, want 1", n)
	}
}

// What Handle did is counted, and after the next list nothing is pending.
func TestTheMetricsCountWhatHappened(t *testing.T) {
	r := start(t, nil)
	defer r.stop()
	r.srv.Add(request(t, "kube-system", "req-m1", "traefik", signer))
	r.srv.Add(request(t, "default", "req-m2", "default", signer))
	waitFor(t, "both answered", func() bool {
		return len(conditions(r.srv.Get("kube-system", "req-m1"))) > 0 && len(conditions(r.srv.Get("default", "req-m2"))) > 0
	})
	time.Sleep(400 * time.Millisecond) // one more resync list
	out := r.reg.Render()
	for _, want := range []string{
		"pod_cert_signer_issued_total 1",
		`pod_cert_signer_denied_total{reason="NoGrant"} 1`,
		"pod_cert_signer_pending_requests 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
