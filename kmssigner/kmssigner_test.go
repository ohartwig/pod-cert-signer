// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

package kmssigner_test

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"git.ole-hartwig.eu/devops/pod-cert-signer/ca"
	"git.ole-hartwig.eu/devops/pod-cert-signer/fake/kmsfake"
	"git.ole-hartwig.eu/devops/pod-cert-signer/kmssigner"
)

// The whole path: a CA certificate signed through the KMS signer is a valid,
// self-verifying certificate for the key KMS holds, and it took exactly one
// DIGEST signature.
func TestACACertificateSignedThroughKMSVerifies(t *testing.T) {
	f := kmsfake.New()
	s, err := kmssigner.New(context.Background(), f, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	der, err := ca.New(s, "test CA", "example.org", time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("self-signature does not verify: %v", err)
	}
	if f.Calls != 1 || f.Seen[0].MessageType != types.MessageTypeDigest || len(f.Seen[0].Message) != 32 {
		t.Fatalf("want one DIGEST call with a 32-byte digest, got %d calls", f.Calls)
	}
}

// A key of the wrong spec or usage is refused at startup.
func TestTheWrongKeyIsRefusedAtStartup(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*kmsfake.KMS)
		want string
	}{
		{"spec", func(f *kmsfake.KMS) { f.Spec = types.KeySpecEccNistP384 }, "ECC_NIST_P256"},
		{"usage", func(f *kmsfake.KMS) { f.Usage = types.KeyUsageTypeEncryptDecrypt }, "SIGN_VERIFY"},
	} {
		f := kmsfake.New()
		tc.mod(f)
		if _, err := kmssigner.New(context.Background(), f, "k"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want an error naming %s, got %v", tc.name, tc.want, err)
		}
	}
}

// A KMS failure surfaces as an error: nothing is issued without a signature.
func TestAKMSFailureIsAnError(t *testing.T) {
	f := kmsfake.New()
	s, _ := kmssigner.New(context.Background(), f, "k")
	f.SignErr = errors.New("ThrottlingException")
	if _, err := ca.New(s, "x", "example.org", time.Now(), time.Hour); err == nil || !strings.Contains(err.Error(), "ThrottlingException") {
		t.Fatalf("want the KMS error, got %v", err)
	}
}
