// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Package kmssigner is the CA key: a crypto.Signer whose private half never
// leaves AWS KMS (design D1). crypto/x509 hands it a SHA-256 digest; KMS signs
// that digest with ECDSA_SHA_256 and MessageType DIGEST and returns the
// signature DER-encoded, which is exactly what x509 expects. Every signature
// is a KMS call, and so a CloudTrail entry.
package kmssigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// API is the part of the KMS client this package uses; *kms.Client
// satisfies it, and fake/kmsfake does too.
type API interface {
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

// Signer signs with one KMS key.
type Signer struct {
	api     API
	keyID   string
	pub     *ecdsa.PublicKey
	timeout time.Duration
}

// New reads the key's public half and refuses anything but a P-256 signing
// key: a key spec mismatch found here is a startup error, not a failed
// signature on the first request.
func New(ctx context.Context, api API, keyID string) (*Signer, error) {
	out, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("kms: GetPublicKey %s: %w", keyID, err)
	}
	if out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("kms: key %s has usage %s, want SIGN_VERIFY", keyID, out.KeyUsage)
	}
	if out.KeySpec != types.KeySpecEccNistP256 {
		return nil, fmt.Errorf("kms: key %s has spec %s, want ECC_NIST_P256", keyID, out.KeySpec)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kms: public key of %s: %w", keyID, err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("kms: public key of %s is %T, want ECDSA P-256", keyID, pub)
	}
	return &Signer{api: api, keyID: keyID, pub: ec, timeout: 10 * time.Second}, nil
}

// Public implements crypto.Signer.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign implements crypto.Signer. The random source is unused: KMS draws its
// own nonce.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("kms: only SHA-256 digests are signed (ECDSA_SHA_256)")
	}
	if len(digest) != crypto.SHA256.Size() {
		return nil, fmt.Errorf("kms: digest is %d bytes, want %d", len(digest), crypto.SHA256.Size())
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	out, err := s.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms: Sign: %w", err)
	}
	return out.Signature, nil
}
