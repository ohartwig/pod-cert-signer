// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

package issuer_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"git.ole-hartwig.eu/devops/pod-cert-signer/ca"
	"git.ole-hartwig.eu/devops/pod-cert-signer/issuer"
	"git.ole-hartwig.eu/devops/pod-cert-signer/policy"
)

var now = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

const testPolicy = `{
  "signerName": "koh.ole-hartwig.eu/workload",
  "trustDomain": "koh.ole-hartwig.eu",
  "dnsNamesAnnotation": "koh.ole-hartwig.eu/dns-names",
  "lifetime": "24h",
  "refreshAt": 0.66,
  "keyTypes": ["ECDSAP256", "ED25519"],
  "grants": [
    {"namespace": "monitoring", "serviceAccount": "crowdsec-loki", "usage": "server",
     "dnsNames": ["crowdsec-loki.monitoring.svc", "crowdsec-loki.monitoring.svc.cluster.local"]},
    {"namespace": "kube-system", "serviceAccount": "traefik", "usage": "client", "ou": "crowdsec-agent"},
    {"namespace": "kunde-*", "serviceAccount": "crowdsec-agent", "usage": "client", "ou": "crowdsec-agent"}
  ]
}`

// newIssuer builds an issuer with a fresh CA. The CA key is a local P-256
// key standing in for KMS; the certificate is built by the same code the
// init subcommand uses, name constraints included.
func newIssuer(t *testing.T) (*issuer.Issuer, *x509.Certificate) {
	t.Helper()
	p, err := policy.Parse([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := ca.New(key, "test workload CA", p.TrustDomain, now, 5*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &issuer.Issuer{Policy: p, CA: issuer.CA{Cert: cert, Signer: key}}, cert
}

// stubCSR does what the kubelet does: an empty PKCS#10 request, signed with
// the freshly generated pod key.
func stubCSR(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func p256(t *testing.T) crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func denied(t *testing.T, err error, want issuer.Reason) {
	t.Helper()
	var d *issuer.Denied
	if !errors.As(err, &d) {
		t.Fatalf("want a denial %s, got %v", want, err)
	}
	if d.Reason != want {
		t.Fatalf("want reason %s, got %s (%s)", want, d.Reason, d.Message)
	}
}

// Check 1 of the design: a ServiceAccount no grant names is denied, and
// nothing is issued.
func TestAnUnnamedServiceAccountGetsNothing(t *testing.T) {
	is, _ := newIssuer(t)
	for _, tc := range []struct{ ns, sa string }{
		{"monitoring", "prometheus"},     // right namespace, wrong SA
		{"kube-system", "crowdsec-loki"}, // right SA name, wrong namespace
		{"kundefoo", "crowdsec-agent"},   // looks like the prefix, is not
		{"default", "default"},
	} {
		got, err := is.Issue(issuer.Request{Namespace: tc.ns, ServiceAccountName: tc.sa, StubPKCS10Request: stubCSR(t, p256(t))}, now)
		denied(t, err, issuer.ReasonNoGrant)
		if got != nil {
			t.Fatalf("%s/%s: a certificate came back with the denial", tc.ns, tc.sa)
		}
	}
}

// Check 2: a DNS name outside the grant denies the whole request instead of
// being dropped.
func TestADNSNameOutsideTheGrantDeniesTheRequest(t *testing.T) {
	is, _ := newIssuer(t)
	for _, want := range []string{
		"crowdsec-loki.monitoring.svc,evil.monitoring.svc",
		"grafana.monitoring.svc",
		"example.com",
	} {
		_, err := is.Issue(issuer.Request{
			Namespace: "monitoring", ServiceAccountName: "crowdsec-loki",
			StubPKCS10Request: stubCSR(t, p256(t)),
			UserAnnotations:   map[string]string{"koh.ole-hartwig.eu/dns-names": want},
		}, now)
		denied(t, err, issuer.ReasonDNSNameNotGranted)
	}
	// And a client grant never carries DNS names, even when asked.
	_, err := is.Issue(issuer.Request{
		Namespace: "kube-system", ServiceAccountName: "traefik",
		StubPKCS10Request: stubCSR(t, p256(t)),
		UserAnnotations:   map[string]string{"koh.ole-hartwig.eu/dns-names": "traefik.kube-system.svc"},
	}, now)
	denied(t, err, issuer.ReasonDNSNameNotGranted)
}

// Check 3: notAfter never exceeds the shorter of the policy lifetime and the
// request's maxExpirationSeconds.
func TestTheLifetimeIsCappedByTheShorterLimit(t *testing.T) {
	is, _ := newIssuer(t)
	for _, tc := range []struct {
		name   string
		maxExp int64
		want   time.Duration
	}{
		{"request asks for more than the policy", 91 * 24 * 3600, 24 * time.Hour},
		{"request asks for less", 2 * 3600, 2 * time.Hour},
		{"request leaves it to the signer", 0, 24 * time.Hour},
	} {
		got, err := is.Issue(issuer.Request{
			Namespace: "kube-system", ServiceAccountName: "traefik",
			MaxExpirationSeconds: tc.maxExp, StubPKCS10Request: stubCSR(t, p256(t)),
		}, now)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		cert, _ := x509.ParseCertificate(got.CertificateDER)
		if want := now.Add(tc.want); !cert.NotAfter.Equal(want) || !got.NotAfter.Equal(want) {
			t.Fatalf("%s: notAfter %s (status %s), want %s", tc.name, cert.NotAfter, got.NotAfter, want)
		}
		if !got.BeginRefreshAt.After(got.NotBefore) || !got.BeginRefreshAt.Before(got.NotAfter) {
			t.Fatalf("%s: beginRefreshAt %s outside the validity", tc.name, got.BeginRefreshAt)
		}
	}
	// Below the API floor of one hour the request is denied, not shortened.
	_, err := is.Issue(issuer.Request{Namespace: "kube-system", ServiceAccountName: "traefik",
		MaxExpirationSeconds: 1800, StubPKCS10Request: stubCSR(t, p256(t))}, now)
	denied(t, err, issuer.ReasonBadLifetime)
}

// Check 4: a key type the policy does not list is denied with
// UnsupportedKeyType, the reason the API understands.
func TestAnUnlistedKeyTypeIsDenied(t *testing.T) {
	is, _ := newIssuer(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, err := is.Issue(issuer.Request{Namespace: "kube-system", ServiceAccountName: "traefik",
		StubPKCS10Request: stubCSR(t, p384)}, now)
	denied(t, err, issuer.ReasonUnsupportedKeyType)

	// The two listed types pass.
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	for _, k := range []crypto.Signer{p256(t), ed} {
		if _, err := is.Issue(issuer.Request{Namespace: "kube-system", ServiceAccountName: "traefik",
			StubPKCS10Request: stubCSR(t, k)}, now); err != nil {
			t.Fatalf("%T: %v", k, err)
		}
	}
}

// A stub request whose signature does not verify names a key its sender
// does not hold.
func TestAForgedStubRequestIsDenied(t *testing.T) {
	is, _ := newIssuer(t)
	der := stubCSR(t, p256(t))
	der[len(der)-1] ^= 0xff // the last byte is part of the signature
	_, err := is.Issue(issuer.Request{Namespace: "kube-system", ServiceAccountName: "traefik", StubPKCS10Request: der}, now)
	denied(t, err, issuer.ReasonBadCSR)
}

// What is issued verifies against the CA, carries the identity the design
// fixes, and passes the CA's name constraints.
func TestAnIssuedServerCertificateVerifiesAndCarriesItsIdentity(t *testing.T) {
	is, caCert := newIssuer(t)
	got, err := is.Issue(issuer.Request{
		Namespace: "monitoring", ServiceAccountName: "crowdsec-loki",
		StubPKCS10Request: stubCSR(t, p256(t)),
		UserAnnotations:   map[string]string{"koh.ole-hartwig.eu/dns-names": "crowdsec-loki.monitoring.svc"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(got.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: "crowdsec-loki.monitoring.svc",
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if leaf.Subject.CommonName != "monitoring/crowdsec-loki" {
		t.Fatalf("CN %q", leaf.Subject.CommonName)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://koh.ole-hartwig.eu/ns/monitoring/sa/crowdsec-loki" {
		t.Fatalf("URIs %v", leaf.URIs)
	}
}

// The name constraints are real: a leaf the CA signs for a public name does
// not verify, even if the policy were bypassed. The certificate is built by
// hand here, around the issuer, because the issuer itself would refuse.
func TestTheCANameConstraintsRejectAPublicName(t *testing.T) {
	is, caCert := newIssuer(t)
	tmpl := &x509.Certificate{
		SerialNumber: big1(), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"git.ole-hartwig.eu"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	pub := p256(t).Public()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, is.CA.Signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "git.ole-hartwig.eu", CurrentTime: now})
	var cie x509.CertificateInvalidError
	if !errors.As(err, &cie) || cie.Reason != x509.CANotAuthorizedForThisName {
		t.Fatalf("want CANotAuthorizedForThisName, got %v", err)
	}
}

func big1() *big.Int { return big.NewInt(1) }
