// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Package controller connects the API to the issuer: every pending request
// addressed to this signer gets exactly one answer, Issued or Denied.
//
// The loop is list, answer what is pending, watch, and list again when the
// watch ends. A resync interval bounds the watch, so a request whose answer
// failed transiently (a KMS timeout, a 409 because the object moved) is
// picked up again by the next list instead of by a retry queue that could
// lose it.
package controller

import (
	"context"
	"encoding/pem"
	"errors"
	"log/slog"
	"time"

	"git.ole-hartwig.eu/devops/pod-cert-signer/issuer"
	"git.ole-hartwig.eu/devops/pod-cert-signer/kube"
)

// API is the part of kube.Client the controller uses.
type API interface {
	List(ctx context.Context) ([]*kube.PodCertificateRequest, string, error)
	Watch(ctx context.Context, rv string, fn func(kube.Event)) (string, error)
	UpdateStatus(ctx context.Context, r *kube.PodCertificateRequest) error
}

// Controller answers PodCertificateRequests for one signer name.
type Controller struct {
	API        API
	Issuer     *issuer.Issuer
	SignerName string
	Now        func() time.Time
	Log        *slog.Logger
	// Resync bounds each watch; the list that follows retries whatever is
	// still pending.
	Resync time.Duration
}

// Handle answers one request if it is ours and still pending. A returned
// error is transient: the request stays pending and the next list retries.
func (c *Controller) Handle(ctx context.Context, r *kube.PodCertificateRequest) error {
	if r.Spec.SignerName != c.SignerName || !r.Pending() {
		return nil
	}
	now := c.Now()
	req := issuer.Request{
		Namespace:          r.Metadata.Namespace,
		PodName:            r.Spec.PodName,
		ServiceAccountName: r.Spec.ServiceAccountName,
		NodeName:           r.Spec.NodeName,
		StubPKCS10Request:  r.Spec.StubPKCS10Request,
		UserAnnotations:    r.Spec.UnverifiedUserAnnotations,
	}
	if r.Spec.MaxExpirationSeconds != nil {
		req.MaxExpirationSeconds = int64(*r.Spec.MaxExpirationSeconds)
	}
	log := c.Log.With("namespace", r.Metadata.Namespace, "request", r.Metadata.Name,
		"serviceAccount", r.Spec.ServiceAccountName, "pod", r.Spec.PodName)

	out, err := c.Issuer.Issue(req, now)
	var denied *issuer.Denied
	switch {
	case errors.As(err, &denied):
		r.Status.Conditions = append(r.Status.Conditions, kube.Condition{
			Type: "Denied", Status: "True", Reason: string(denied.Reason), Message: denied.Message,
			LastTransitionTime: now.UTC().Truncate(time.Second), ObservedGeneration: r.Metadata.Generation,
		})
		if err := c.API.UpdateStatus(ctx, r); err != nil {
			log.Error("writing the denial failed, will retry", "err", err)
			return err
		}
		log.Warn("denied", "reason", denied.Reason, "message", denied.Message)
		return nil
	case err != nil:
		log.Error("issue failed, will retry", "err", err)
		return err
	}

	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: out.CertificateDER})
	nb, na, br := out.NotBefore.UTC(), out.NotAfter.UTC(), out.BeginRefreshAt.UTC()
	r.Status.CertificateChain = string(chain)
	r.Status.NotBefore, r.Status.NotAfter, r.Status.BeginRefreshAt = &nb, &na, &br
	r.Status.Conditions = append(r.Status.Conditions, kube.Condition{
		Type: "Issued", Status: "True", Reason: "Issued", Message: "issued by " + c.SignerName,
		LastTransitionTime: now.UTC().Truncate(time.Second), ObservedGeneration: r.Metadata.Generation,
	})
	// A failed status write used to return here silently, and Run discards
	// the error: the first deployment answered nothing for twenty minutes
	// and logged nothing. Every failure is logged where it happens.
	if err := c.API.UpdateStatus(ctx, r); err != nil {
		log.Error("writing the certificate failed, will retry", "err", err)
		return err
	}
	log.Info("issued", "notAfter", na)
	return nil
}

// Run lists, answers, watches, and repeats until ctx ends.
func (c *Controller) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		items, rv, err := c.API.List(ctx)
		if err != nil {
			c.Log.Error("list failed", "err", err)
			sleep(ctx, 5*time.Second)
			continue
		}
		for _, r := range items {
			_ = c.Handle(ctx, r) // logged inside; retried by the next list
		}
		wctx, cancel := context.WithTimeout(ctx, c.Resync)
		_, err = c.API.Watch(wctx, rv, func(ev kube.Event) {
			if ev.Type == "ADDED" || ev.Type == "MODIFIED" {
				_ = c.Handle(ctx, ev.Object)
			}
		})
		cancel()
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, kube.ErrGone) && ctx.Err() == nil {
			c.Log.Warn("watch ended", "err", err)
			sleep(ctx, time.Second)
		}
	}
	return ctx.Err()
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
