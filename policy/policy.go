// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Package policy is the part of the signer that decides who is who. It is a
// file in the cluster's GitOps repository, so every change to it is a
// reviewed merge request, and it denies by default: a ServiceAccount no grant
// names gets nothing.
//
// Parse is strict on purpose. An unknown key, a bare "*" namespace or a
// malformed DNS name is an error, and a signer that cannot parse its policy
// issues nothing (design D6: fail closed). Whether the DNS names lie inside
// the CA's name constraints is checked against the CA certificate itself, by
// CheckNameConstraints, because only the certificate knows them.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Usage is what a certificate may be presented for.
type Usage string

const (
	UsageClient Usage = "client"
	UsageServer Usage = "server"
	// UsageServerAndClient is for a workload that both serves and dials out
	// with the same identity, like a proxy in front of an application.
	UsageServerAndClient Usage = "server-and-client"
)

// Serves reports whether a certificate for this usage carries serverAuth
// (and therefore DNS names).
func (u Usage) Serves() bool { return u == UsageServer || u == UsageServerAndClient }

// Dials reports whether a certificate for this usage carries clientAuth.
func (u Usage) Dials() bool { return u == UsageClient || u == UsageServerAndClient }

// KeyType names the subject key types the kubelet can generate. The API
// accepts RSA3072, RSA4096, ECDSAP256, ECDSAP384, ECDSAP521 and ED25519.
type KeyType string

var knownKeyTypes = map[KeyType]bool{
	"RSA3072": true, "RSA4096": true,
	"ECDSAP256": true, "ECDSAP384": true, "ECDSAP521": true,
	"ED25519": true,
}

// Grant says which certificate one ServiceAccount (or one ServiceAccount name
// in a family of namespaces) may receive.
type Grant struct {
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"serviceAccount"`
	Usage          Usage    `json:"usage"`
	OU             string   `json:"ou,omitempty"`
	DNSNames       []string `json:"dnsNames,omitempty"`
}

// Policy is the whole file.
type Policy struct {
	SignerName string `json:"signerName"`
	// TrustDomain is the SPIFFE trust domain of every issued identity
	// (spiffe://<trustDomain>/ns/<ns>/sa/<sa>). It must match the CA's URI
	// name constraint.
	TrustDomain string `json:"trustDomain"`
	// DNSNamesAnnotation is the pod annotation key through which a pod asks
	// for DNS names. Domain-prefixed, as the API requires for
	// unverifiedUserAnnotations.
	DNSNamesAnnotation string    `json:"dnsNamesAnnotation"`
	Lifetime           Duration  `json:"lifetime"`
	RefreshAt          float64   `json:"refreshAt"`
	KeyTypes           []KeyType `json:"keyTypes"`
	Grants             []Grant   `json:"grants"`
}

// Duration is a time.Duration written as "24h" in the file.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"24h\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// minLifetime is the API's floor: kube-apiserver rejects a certificate that
// lives shorter than one hour.
const minLifetime = time.Hour

// Parse reads and validates a policy. Every rule here has a test that feeds
// it the violation.
func Parse(data []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if dec.More() {
		return nil, errors.New("policy: trailing data after the policy object")
	}
	if p.SignerName == "" {
		return nil, errors.New("policy: signerName is empty")
	}
	if p.TrustDomain == "" || strings.ContainsAny(p.TrustDomain, "/:") {
		return nil, fmt.Errorf("policy: trustDomain %q must be a bare host name", p.TrustDomain)
	}
	if prefix, name, ok := strings.Cut(p.DNSNamesAnnotation, "/"); !ok || !strings.Contains(prefix, ".") || name == "" {
		return nil, fmt.Errorf("policy: dnsNamesAnnotation %q must be domain-prefixed, like example.com/dns-names", p.DNSNamesAnnotation)
	}
	if time.Duration(p.Lifetime) < minLifetime {
		return nil, fmt.Errorf("policy: lifetime %s is below the API floor of %s", time.Duration(p.Lifetime), minLifetime)
	}
	// The API wants beginRefreshAt at least 10 minutes after notBefore and 10
	// minutes before notAfter. With the shortest lifetime it accepts, one
	// hour, that is refreshAt in [1/6, 5/6]; outside it some request would be
	// refused.
	if p.RefreshAt < 0.17 || p.RefreshAt > 0.83 {
		return nil, fmt.Errorf("policy: refreshAt %v must be between 0.17 and 0.83 (10 minutes from either end of a 1 h certificate)", p.RefreshAt)
	}
	if len(p.KeyTypes) == 0 {
		return nil, errors.New("policy: keyTypes is empty")
	}
	for _, k := range p.KeyTypes {
		if !knownKeyTypes[k] {
			return nil, fmt.Errorf("policy: unknown key type %q", k)
		}
	}
	for i, g := range p.Grants {
		if err := g.validate(); err != nil {
			return nil, fmt.Errorf("policy: grant %d (%s/%s): %w", i, g.Namespace, g.ServiceAccount, err)
		}
	}
	return &p, nil
}

func (g Grant) validate() error {
	switch {
	case g.Namespace == "":
		return errors.New("namespace is empty")
	case g.Namespace == "*":
		return errors.New(`a bare "*" namespace grants every namespace; name them or use a prefix like "tenant-*"`)
	case strings.Contains(strings.TrimSuffix(g.Namespace, "*"), "*"):
		return errors.New(`"*" is allowed only as the last character of the namespace`)
	case g.ServiceAccount == "" || strings.Contains(g.ServiceAccount, "*"):
		return errors.New("serviceAccount must be a single, literal name")
	}
	switch {
	case g.Usage != UsageClient && g.Usage != UsageServer && g.Usage != UsageServerAndClient:
		return fmt.Errorf("usage %q is none of %q, %q, %q", g.Usage, UsageClient, UsageServer, UsageServerAndClient)
	case !g.Usage.Serves() && len(g.DNSNames) > 0:
		return errors.New("a client grant carries no dnsNames")
	case g.Usage.Serves() && len(g.DNSNames) == 0:
		return fmt.Errorf("a %s grant needs at least one dnsName", g.Usage)
	}
	for _, n := range g.DNSNames {
		if !validDNSName(n) {
			return fmt.Errorf("dnsName %q is not a DNS name", n)
		}
	}
	return nil
}

// validDNSName accepts lower-case labels of letters, digits and hyphens, not
// starting or ending with a hyphen. No wildcard, no trailing dot, no IP.
func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// CheckNameConstraints fails if any granted DNS name lies outside the CA
// certificate's permitted DNS domains (design D2). A grant like that could
// never be honoured: a constraint-aware client rejects the chain at the
// handshake, where nobody looks. A CA without DNS constraints is refused as
// well; the design requires them, and a signer should not quietly run
// without.
func (p *Policy) CheckNameConstraints(permitted []string) error {
	if len(permitted) == 0 {
		return errors.New("policy: the CA certificate carries no permitted DNS domains")
	}
	for i, g := range p.Grants {
		for _, n := range g.DNSNames {
			if !PermittedDNS(n, permitted) {
				return fmt.Errorf("policy: grant %d (%s/%s): dnsName %q is outside the CA's name constraints %v", i, g.Namespace, g.ServiceAccount, n, permitted)
			}
		}
	}
	return nil
}

// PermittedDNS reports whether name satisfies one of the permitted domains,
// with the semantics of RFC 5280 as Go's crypto/x509 applies them: a domain
// "svc" permits "svc" itself and every name below it; a domain written with a
// leading dot, ".svc", permits only names below it.
func PermittedDNS(name string, permitted []string) bool {
	for _, d := range permitted {
		if sub, ok := strings.CutPrefix(d, "."); ok {
			if strings.HasSuffix(name, "."+sub) {
				return true
			}
			continue
		}
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// Lookup returns the grant for a ServiceAccount, or nil. An exact namespace
// wins over a prefix, so a narrower grant can never be shadowed by a family.
func (p *Policy) Lookup(namespace, serviceAccount string) *Grant {
	var prefix *Grant
	for i := range p.Grants {
		g := &p.Grants[i]
		if g.ServiceAccount != serviceAccount {
			continue
		}
		if g.Namespace == namespace {
			return g
		}
		if base, ok := strings.CutSuffix(g.Namespace, "*"); ok && strings.HasPrefix(namespace, base) && prefix == nil {
			prefix = g
		}
	}
	return prefix
}

// AllowsKeyType reports whether the policy accepts a subject key type.
func (p *Policy) AllowsKeyType(k KeyType) bool {
	return slices.Contains(p.KeyTypes, k)
}
