// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Package issuer turns one PodCertificateRequest into either a denial with a
// reason or a signed leaf certificate. It knows nothing about the Kubernetes
// API or KMS: the request arrives as a plain struct, the CA key as a
// crypto.Signer, and the clock as a parameter. That is what makes the four
// checks of the design testable without a cluster.
package issuer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ohartwig/pod-cert-signer/policy"
)

// Request carries the fields of a PodCertificateRequest the decision uses.
// Everything except UserAnnotations is filled in by the API server from the
// pod itself.
type Request struct {
	Namespace            string
	PodName              string
	ServiceAccountName   string
	NodeName             string
	MaxExpirationSeconds int64
	StubPKCS10Request    []byte // DER
	UserAnnotations      map[string]string
}

// Reason is the machine-readable cause of a denial. UnsupportedKeyType is
// the one reason the API treats specially.
type Reason string

const (
	ReasonNoGrant            Reason = "NoGrant"
	ReasonUnsupportedKeyType Reason = "UnsupportedKeyType"
	ReasonDNSNameNotGranted  Reason = "DNSNameNotGranted"
	ReasonBadCSR             Reason = "InvalidStubPKCS10Request"
	ReasonBadLifetime        Reason = "InvalidMaxExpiration"
)

// Denied is returned when the request must be denied; the controller writes
// Reason and Message into the Denied condition.
type Denied struct {
	Reason  Reason
	Message string
}

func (d *Denied) Error() string { return string(d.Reason) + ": " + d.Message }

// Issued is what goes into the request's status.
type Issued struct {
	CertificateDER []byte
	NotBefore      time.Time
	NotAfter       time.Time
	BeginRefreshAt time.Time
}

// CA is the signing side: the CA certificate and a signer for its key. In
// production the signer is KMS; in tests it is a local key.
type CA struct {
	Cert   *x509.Certificate
	Signer crypto.Signer
}

// Issuer holds the policy and the CA.
type Issuer struct {
	Policy *policy.Policy
	CA     CA
}

// apiFloor is kube-apiserver's minimum lifetime for a pod certificate.
const apiFloor = time.Hour

// clockSkew backdates notBefore so that a node whose clock runs slightly
// behind still accepts the certificate. It has to stay well inside the API's
// own window: kube-apiserver rejects a status.notBefore that is not "within 5
// minutes of kube-apiserver's current time". Five minutes exactly, plus the
// truncation to whole seconds, was just outside it - the third rule the
// first deployment met (2026-09-25).
const clockSkew = time.Minute

// Issue decides the request and, if it is allowed, signs a leaf. A *Denied
// error means "write a Denied condition"; any other error is transient and
// the request is retried.
func (is *Issuer) Issue(req Request, now time.Time) (*Issued, error) {
	g := is.Policy.Lookup(req.Namespace, req.ServiceAccountName)
	if g == nil {
		return nil, &Denied{ReasonNoGrant, fmt.Sprintf("no grant for %s/%s", req.Namespace, req.ServiceAccountName)}
	}

	csr, err := x509.ParseCertificateRequest(req.StubPKCS10Request)
	if err != nil {
		return nil, &Denied{ReasonBadCSR, err.Error()}
	}
	// Proof of possession: the kubelet signs the stub request with the key it
	// generated. A request whose signature does not verify names a key its
	// sender does not hold.
	if err := csr.CheckSignature(); err != nil {
		return nil, &Denied{ReasonBadCSR, "signature does not verify: " + err.Error()}
	}
	kt, err := keyType(csr.PublicKey)
	if err != nil || !is.Policy.AllowsKeyType(kt) {
		return nil, &Denied{ReasonUnsupportedKeyType, fmt.Sprintf("key type %q is not accepted; use one of %v", kt, is.Policy.KeyTypes)}
	}

	// The annotation arrives in unverifiedUserAnnotations: a wish, never a
	// fact. The grant decides.
	dnsNames, err := grantedDNSNames(g, req.UserAnnotations[is.Policy.DNSNamesAnnotation])
	if err != nil {
		return nil, err
	}

	lifetime := time.Duration(is.Policy.Lifetime)
	if req.MaxExpirationSeconds > 0 {
		lifetime = min(lifetime, time.Duration(req.MaxExpirationSeconds)*time.Second)
	}
	if lifetime < apiFloor {
		return nil, &Denied{ReasonBadLifetime, fmt.Sprintf("the allowed lifetime %s is below the API floor %s", lifetime, apiFloor)}
	}

	// The lifetime counts from notBefore, backdating included. The API
	// rejects a certificate whose notAfter - notBefore exceeds the request's
	// maxExpirationSeconds; `now + lifetime` with a backdated notBefore made
	// every 24 h certificate 24 h 5 min long, and every status write failed
	// (first deployment, 2026-09-25).
	//
	// Whole seconds, too: an X.509 time carries no fraction, and the API
	// requires status.notBefore/notAfter to EQUAL the leaf's. A status time
	// with nanoseconds never does.
	notBefore := now.Truncate(time.Second).Add(-clockSkew)
	notAfter := notBefore.Add(lifetime)
	// Whole seconds like the other two times; the API wants it inside
	// [notBefore+10min, notAfter-10min], which refreshAt in (0,1) of a
	// lifetime of at least one hour keeps for any refreshAt in [0.17, 0.83].
	refresh := notBefore.Add(time.Duration(is.Policy.RefreshAt * float64(notAfter.Sub(notBefore)))).Truncate(time.Second)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	id := &url.URL{Scheme: "spiffe", Host: is.Policy.TrustDomain, Path: "/ns/" + req.Namespace + "/sa/" + req.ServiceAccountName}
	subject := pkix.Name{CommonName: req.Namespace + "/" + req.ServiceAccountName}
	if g.OU != "" {
		subject.OrganizationalUnit = []string{g.OU}
	}
	var eku []x509.ExtKeyUsage
	if g.Usage.Serves() {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	if g.Usage.Dials() {
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		URIs:                  []*url.URL{id},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, is.CA.Cert, csr.PublicKey, is.CA.Signer)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return &Issued{CertificateDER: der, NotBefore: notBefore, NotAfter: notAfter, BeginRefreshAt: refresh}, nil
}

// grantedDNSNames returns the requested names if every one of them is in the
// grant. A single name outside it denies the whole request: silently dropping
// it would hand the pod a certificate that fails later, at the handshake,
// where nobody looks.
func grantedDNSNames(g *policy.Grant, requested string) ([]string, error) {
	var names []string
	for n := range strings.SplitSeq(requested, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	if !g.Usage.Serves() {
		if len(names) > 0 {
			return nil, &Denied{ReasonDNSNameNotGranted, "a client grant carries no DNS names"}
		}
		return nil, nil
	}
	if len(names) == 0 {
		return g.DNSNames, nil
	}
	for _, n := range names {
		if !slices.Contains(g.DNSNames, n) {
			return nil, &Denied{ReasonDNSNameNotGranted, fmt.Sprintf("%q is not granted to this ServiceAccount", n)}
		}
	}
	return names, nil
}

func keyType(pub any) (policy.KeyType, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "ECDSAP256", nil
		case elliptic.P384():
			return "ECDSAP384", nil
		case elliptic.P521():
			return "ECDSAP521", nil
		}
	case ed25519.PublicKey:
		return "ED25519", nil
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 3072:
			return "RSA3072", nil
		case 4096:
			return "RSA4096", nil
		}
	}
	return "", errors.New("unsupported public key")
}
