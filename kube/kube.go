// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Package kube is the signer's whole view of the Kubernetes API: list and
// watch PodCertificateRequests, and write one request's status. Plain
// net/http and encoding/json (design D4) - client-go would bring some fifty
// modules into the most privileged component for these calls.
package kube

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const apiPath = "/apis/certificates.k8s.io/v1"

// PodCertificateRequest mirrors the fields of certificates.k8s.io/v1 the
// signer reads or writes. Unknown fields survive a status update because the
// update sends back the object as it was read, with only Status changed.
type PodCertificateRequest struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   Metadata        `json:"metadata"`
	Spec       Spec            `json:"spec"`
	Status     Status          `json:"status"`
	Raw        json.RawMessage `json:"-"`
}

type Metadata struct {
	Name              string    `json:"name"`
	Namespace         string    `json:"namespace"`
	ResourceVersion   string    `json:"resourceVersion,omitempty"`
	Generation        int64     `json:"generation,omitempty"`
	CreationTimestamp time.Time `json:"creationTimestamp,omitzero"`
}

type Spec struct {
	SignerName                string            `json:"signerName"`
	PodName                   string            `json:"podName"`
	PodUID                    string            `json:"podUID"`
	ServiceAccountName        string            `json:"serviceAccountName"`
	ServiceAccountUID         string            `json:"serviceAccountUID"`
	NodeName                  string            `json:"nodeName"`
	NodeUID                   string            `json:"nodeUID"`
	MaxExpirationSeconds      *int32            `json:"maxExpirationSeconds,omitempty"`
	StubPKCS10Request         []byte            `json:"stubPKCS10Request"` // base64 in JSON
	UnverifiedUserAnnotations map[string]string `json:"unverifiedUserAnnotations,omitempty"`
}

type Status struct {
	Conditions       []Condition `json:"conditions,omitempty"`
	CertificateChain string      `json:"certificateChain,omitempty"`
	NotBefore        *time.Time  `json:"notBefore,omitempty"`
	BeginRefreshAt   *time.Time  `json:"beginRefreshAt,omitempty"`
	NotAfter         *time.Time  `json:"notAfter,omitempty"`
}

type Condition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason"`
	Message            string    `json:"message"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
	ObservedGeneration int64     `json:"observedGeneration,omitempty"`
}

// Pending reports whether nobody has answered the request yet. Issued,
// Denied and Failed are terminal: the API makes them immutable.
func (r *PodCertificateRequest) Pending() bool {
	if r.Status.CertificateChain != "" {
		return false
	}
	for _, c := range r.Status.Conditions {
		switch c.Type {
		case "Issued", "Denied", "Failed":
			return false
		}
	}
	return true
}

// Client talks to one API server.
type Client struct {
	Base      string       // https://host:port
	HTTP      *http.Client // carries the CA
	TokenFile string       // re-read on every call: projected tokens rotate
	Token     string       // fixed token, for tests
}

// InCluster builds a client from the ServiceAccount volume and the service
// environment, the way every pod finds its API server.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST/PORT not set: not running in a cluster")
	}
	const sa = "/var/run/secrets/kubernetes.io/serviceaccount/"
	pem, err := os.ReadFile(sa + "ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificate in " + sa + "ca.crt")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	return &Client{
		Base:      "https://" + net.JoinHostPort(host, port),
		HTTP:      &http.Client{Transport: tr},
		TokenFile: sa + "token",
	}, nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
	if err != nil {
		return nil, err
	}
	tok := c.Token
	if c.TokenFile != "" {
		b, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return nil, err
		}
		tok = strings.TrimSpace(string(b))
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.HTTP.Do(req)
}

// StatusError carries the API's HTTP status, so callers can tell a conflict
// (retry with a fresh object) from a gone watch (relist) from everything else.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("api: HTTP %d: %s", e.Code, e.Body) }

// IsConflict reports a 409: someone else wrote the object first.
func IsConflict(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusConflict
}

func check(resp *http.Response) error {
	if resp.StatusCode/100 == 2 {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(b))}
}

type list struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []json.RawMessage `json:"items"`
}

func decode(raw json.RawMessage) (*PodCertificateRequest, error) {
	var r PodCertificateRequest
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	r.Raw = raw
	return &r, nil
}

// List returns every request in the cluster and the resourceVersion to watch
// from. Filtering by signer happens in the caller, so this works whether or
// not the server supports a field selector on spec.signerName.
func (c *Client) List(ctx context.Context) ([]*PodCertificateRequest, string, error) {
	resp, err := c.do(ctx, http.MethodGet, apiPath+"/podcertificaterequests", nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if err := check(resp); err != nil {
		return nil, "", err
	}
	var l list
	if err := json.NewDecoder(resp.Body).Decode(&l); err != nil {
		return nil, "", err
	}
	out := make([]*PodCertificateRequest, 0, len(l.Items))
	for _, raw := range l.Items {
		r, err := decode(raw)
		if err != nil {
			return nil, "", err
		}
		out = append(out, r)
	}
	return out, l.Metadata.ResourceVersion, nil
}

// Event is one line of a watch stream.
type Event struct {
	Type   string // ADDED, MODIFIED, DELETED, BOOKMARK, ERROR
	Object *PodCertificateRequest
}

// ErrGone means the resourceVersion is too old: list again.
var ErrGone = errors.New("watch: resourceVersion expired (410)")

// Watch streams events from rv until the context ends, the server closes the
// stream, or the resourceVersion is gone. It calls fn for every event and
// returns the last resourceVersion it saw, so the caller can resume.
func (c *Client) Watch(ctx context.Context, rv string, fn func(Event)) (string, error) {
	path := apiPath + "/podcertificaterequests?watch=1&allowWatchBookmarks=true&resourceVersion=" + rv
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return rv, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone {
		return rv, ErrGone
	}
	if err := check(resp); err != nil {
		return rv, err
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		var ev struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return rv, err
		}
		if ev.Type == "ERROR" {
			var st struct {
				Code int `json:"code"`
			}
			_ = json.Unmarshal(ev.Object, &st)
			if st.Code == http.StatusGone {
				return rv, ErrGone
			}
			return rv, fmt.Errorf("watch: error event %s", ev.Object)
		}
		obj, err := decode(ev.Object)
		if err != nil {
			return rv, err
		}
		if obj.Metadata.ResourceVersion != "" {
			rv = obj.Metadata.ResourceVersion
		}
		if ev.Type != "BOOKMARK" {
			fn(Event{Type: ev.Type, Object: obj})
		}
	}
	return rv, sc.Err()
}

// UpdateStatus writes r.Status through the status subresource. The body is
// the object as it was read with only status replaced, so fields this
// package does not model are sent back untouched, and the resourceVersion
// makes the write conditional: a stale object gets a 409, not an overwrite.
func (c *Client) UpdateStatus(ctx context.Context, r *PodCertificateRequest) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(r.Raw, &obj); err != nil {
		return err
	}
	st, err := json.Marshal(r.Status)
	if err != nil {
		return err
	}
	obj["status"] = st
	body, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("%s/namespaces/%s/podcertificaterequests/%s/status", apiPath, r.Metadata.Namespace, r.Metadata.Name)
	resp, err := c.do(ctx, http.MethodPut, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return check(resp)
}
