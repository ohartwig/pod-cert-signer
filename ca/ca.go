// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Package ca builds the self-signed CA certificate. It is used once per CA
// key, by the `init` subcommand, and its output goes into the cluster's GitOps
// repository by merge request, so the creation of a trust anchor is a reviewed
// artefact and not a line in someone's shell history.
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// PermittedDNSDomains are the name constraints of design D2. In Go's
// semantics a constraint "svc" permits "svc" and every name below it.
var PermittedDNSDomains = []string{"svc", "svc.cluster.local"}

// New signs a CA certificate for the key behind signer. The certificate may
// sign leaves only (path length 0), only for in-cluster DNS names and only
// for identities in the given SPIFFE trust domain. The constraints are
// marked critical, so a verifier that does not understand them rejects the
// chain instead of ignoring them.
func New(signer crypto.Signer, cn, trustDomain string, now time.Time, validity time.Duration) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: cn},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.Add(validity),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         PermittedDNSDomains,
		PermittedURIDomains:         []string{trustDomain},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
}
