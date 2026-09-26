// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Command pod-cert-signer answers PodCertificateRequests for one signer name.
//
//	pod-cert-signer run   answer requests (the Deployment)
//	pod-cert-signer init  create the self-signed CA for a KMS key and print it
//
// Configuration is environment only, so the Deployment is the whole record
// of how it runs:
//
//	POLICY_FILE   policy JSON                 (/etc/pod-cert-signer/policy.json)
//	CA_CERT_FILE  CA certificate PEM          (/etc/pod-cert-signer/ca.crt)
//	KMS_KEY_ID    KMS key id, ARN or alias    (required)
//	METRICS_ADDR  /metrics and /healthz       (:9090)
//	AWS_REGION and the IRSA variables the pod identity webhook sets
//
// time.Now is read here and nowhere else; every package below takes the
// clock as a parameter.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/ohartwig/pod-cert-signer/ca"
	"github.com/ohartwig/pod-cert-signer/controller"
	"github.com/ohartwig/pod-cert-signer/issuer"
	"github.com/ohartwig/pod-cert-signer/kmssigner"
	"github.com/ohartwig/pod-cert-signer/kube"
	"github.com/ohartwig/pod-cert-signer/metrics"
	"github.com/ohartwig/pod-cert-signer/policy"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pod-cert-signer run|init")
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "run":
		err = run(ctx, log)
	case "init":
		err = initCA(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("exit", "err", err)
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func kmsSigner(ctx context.Context) (*kmssigner.Signer, error) {
	keyID := os.Getenv("KMS_KEY_ID")
	if keyID == "" {
		return nil, errors.New("KMS_KEY_ID is not set")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return kmssigner.New(ctx, kms.NewFromConfig(cfg), keyID)
}

func run(ctx context.Context, log *slog.Logger) error {
	policyFile := env("POLICY_FILE", "/etc/pod-cert-signer/policy.json")
	raw, err := os.ReadFile(policyFile)
	if err != nil {
		return err
	}
	pol, err := policy.Parse(raw)
	if err != nil {
		return err // fail closed: no policy, no signer
	}
	caCert, err := readCert(env("CA_CERT_FILE", "/etc/pod-cert-signer/ca.crt"))
	if err != nil {
		return err
	}
	signer, err := kmsSigner(ctx)
	if err != nil {
		return err
	}
	// The CA certificate in the ConfigMap and the key in KMS must be halves of
	// one pair. Checked here, so a mismatch is a CrashLoop at deploy time and
	// not a day of leaves that no client accepts.
	if !signer.Public().(*ecdsa.PublicKey).Equal(caCert.PublicKey) {
		return errors.New("the CA certificate does not belong to the KMS key")
	}
	api, err := kube.InCluster()
	if err != nil {
		return err
	}
	// A policy change arrives as a new ConfigMap revision. Reloading in place
	// would need its own tests for half-written files; exiting lets the
	// Deployment restart with the new file, and a bad one CrashLoops -
	// which is the fail-closed behaviour the design asks for.
	go watchFile(ctx, log, policyFile, raw)
	reg := metrics.New()
	srv := &http.Server{Addr: env("METRICS_ADDR", ":9090"), Handler: reg.Handler(time.Now, 3*time.Minute), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server", "err", err)
		}
	}()
	c := &controller.Controller{
		Metrics:    reg,
		API:        api,
		Issuer:     &issuer.Issuer{Policy: pol, CA: issuer.CA{Cert: caCert, Signer: signer}},
		SignerName: pol.SignerName,
		Now:        time.Now,
		Log:        log,
		Resync:     time.Minute,
	}
	log.Info("started", "signer", pol.SignerName, "grants", len(pol.Grants), "caNotAfter", caCert.NotAfter)
	return c.Run(ctx)
}

func watchFile(ctx context.Context, log *slog.Logger, path string, current []byte) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b, err := os.ReadFile(path)
			if err == nil && string(b) != string(current) {
				log.Info("policy changed; exiting so the Deployment restarts with it")
				os.Exit(0)
			}
		}
	}
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no PEM certificate", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

// initCA creates the CA certificate for the KMS key and prints it. It is run
// once per key, by hand, and its output goes into koh-gitops by merge
// request - the trust anchor is a reviewed artefact.
func initCA(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	cn := fs.String("cn", "", "subject common name of the CA (required)")
	td := fs.String("trust-domain", "", "SPIFFE trust domain for the URI name constraint (required)")
	validity := fs.Duration("validity", 5*365*24*time.Hour, "CA certificate validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cn == "" || *td == "" {
		return errors.New("init needs -cn and -trust-domain")
	}
	signer, err := kmsSigner(ctx)
	if err != nil {
		return err
	}
	der, err := ca.New(signer, *cn, *td, time.Now(), *validity)
	if err != nil {
		return err
	}
	return pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}
