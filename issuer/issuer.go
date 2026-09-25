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

	"git.ole-hartwig.eu/devops/pod-cert-signer/policy"
)

// DNSNamesAnnotation is how a pod asks for DNS names. It arrives in the
// request's unverifiedUserAnnotations, so it is a wish, never a fact: the
// grant decides.
const DNSNamesAnnotation = "koh.ole-hartwig.eu/dns-names"

// TrustDomain is the SPIFFE trust domain of every issued identity.
const TrustDomain = "koh.ole-hartwig.eu"

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
// behind still accepts the certificate.
const clockSkew = 5 * time.Minute

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

	dnsNames, err := grantedDNSNames(g, req.UserAnnotations[DNSNamesAnnotation])
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

	notBefore := now.Add(-clockSkew)
	notAfter := now.Add(lifetime)
	refresh := notBefore.Add(time.Duration(is.Policy.RefreshAt * float64(notAfter.Sub(notBefore))))

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	id := &url.URL{Scheme: "spiffe", Host: TrustDomain, Path: "/ns/" + req.Namespace + "/sa/" + req.ServiceAccountName}
	subject := pkix.Name{CommonName: req.Namespace + "/" + req.ServiceAccountName}
	if g.OU != "" {
		subject.OrganizationalUnit = []string{g.OU}
	}
	eku := x509.ExtKeyUsageClientAuth
	if g.Usage == policy.UsageServer {
		eku = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
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
	if g.Usage == policy.UsageClient {
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
