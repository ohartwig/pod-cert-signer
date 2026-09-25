// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Package kmsfake answers GetPublicKey and Sign the way KMS does for an
// ECC_NIST_P256 SIGN_VERIFY key, with a local key: a DER-encoded public key,
// and for MessageType DIGEST a DER-encoded ECDSA signature over the digest as
// given. Error paths are exported fields.
package kmsfake

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMS is the fake.
type KMS struct {
	Key     *ecdsa.PrivateKey
	Spec    types.KeySpec // defaults to ECC_NIST_P256
	Usage   types.KeyUsageType
	SignErr error // returned by Sign when set
	Calls   int   // Sign calls, for the "every signature is a KMS call" check
	Seen    []*kms.SignInput
}

// New makes a fake with a fresh P-256 key.
func New() *KMS {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &KMS{Key: k, Spec: types.KeySpecEccNistP256, Usage: types.KeyUsageTypeSignVerify}
}

func (f *KMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	der, err := x509.MarshalPKIXPublicKey(&f.Key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{PublicKey: der, KeySpec: f.Spec, KeyUsage: f.Usage}, nil
}

func (f *KMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.Calls++
	f.Seen = append(f.Seen, in)
	if f.SignErr != nil {
		return nil, f.SignErr
	}
	if in.MessageType != types.MessageTypeDigest || in.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 {
		return nil, errors.New("kmsfake: only DIGEST with ECDSA_SHA_256 is modelled")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, f.Key, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}
