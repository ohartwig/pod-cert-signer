// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

// Package kubefake is an API server that speaks the part of
// certificates.k8s.io/v1 the signer uses: list and watch
// PodCertificateRequests, and PUT their status - with the rules the real one
// enforces that matter here: a stale resourceVersion is a 409, and a request
// that already carries Issued, Denied or Failed cannot be answered again.
//
// Error paths are switched on through exported fields (ConflictNext), not a
// mock framework.
package kubefake

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
)

// Server is the fake. Create with New, stop with Close.
type Server struct {
	*httptest.Server

	// ConflictNext makes the next N status updates fail with 409, as if
	// someone else had written the object first.
	ConflictNext int
	// Token is the bearer token the server accepts; anything else is 401.
	Token string

	mu       sync.Mutex
	rv       int
	objs     map[string]map[string]any // "ns/name" -> object
	watchers []chan event
	updates  int
}

type event struct {
	Type   string         `json:"type"`
	Object map[string]any `json:"object"`
}

// New starts the fake.
func New(token string) *Server {
	s := &Server{Token: token, objs: map[string]map[string]any{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	return s
}

// Add creates a request, as the kubelet would, and notifies watchers.
func (s *Server) Add(obj map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rv++
	md := obj["metadata"].(map[string]any)
	md["resourceVersion"] = strconv.Itoa(s.rv)
	s.objs[md["namespace"].(string)+"/"+md["name"].(string)] = obj
	s.notify("ADDED", obj)
}

// Get returns a copy of the stored object.
func (s *Server) Get(ns, name string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.objs[ns+"/"+name])
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// Updates counts accepted status writes.
func (s *Server) Updates() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updates
}

func (s *Server) notify(typ string, obj map[string]any) {
	for _, w := range s.watchers {
		select {
		case w <- event{typ, obj}:
		default:
		}
	}
}

const base = "/apis/certificates.k8s.io/v1"

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.Token {
		http.Error(w, `{"code":401}`, http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == base+"/podcertificaterequests" && r.URL.Query().Get("watch") == "1":
		s.watch(w, r)
	case r.Method == http.MethodGet && r.URL.Path == base+"/podcertificaterequests":
		s.list(w)
	case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/status"):
		s.putStatus(w, r)
	default:
		http.Error(w, `{"code":404}`, http.StatusNotFound)
	}
}

func (s *Server) list(w http.ResponseWriter) {
	s.mu.Lock()
	// Like the real API: items of a list carry no apiVersion and kind.
	items := make([]map[string]any, 0, len(s.objs))
	for _, o := range s.objs {
		it := map[string]any{}
		for k, v := range o {
			if k != "apiVersion" && k != "kind" {
				it[k] = v
			}
		}
		items = append(items, it)
	}
	rv := s.rv
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"apiVersion": "certificates.k8s.io/v1", "kind": "PodCertificateRequestList",
		"metadata": map[string]any{"resourceVersion": strconv.Itoa(rv)}, "items": items,
	})
}

func (s *Server) watch(w http.ResponseWriter, r *http.Request) {
	ch := make(chan event, 64)
	s.mu.Lock()
	s.watchers = append(s.watchers, ch)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		for i, c := range s.watchers {
			if c == ch {
				s.watchers = append(s.watchers[:i], s.watchers[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	}()
	fl := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			_ = enc.Encode(ev)
			fl.Flush()
		}
	}
}

func (s *Server) putStatus(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, base+"/namespaces/"), "/")
	if len(parts) != 4 || parts[1] != "podcertificaterequests" {
		http.Error(w, `{"code":404}`, http.StatusNotFound)
		return
	}
	key := parts[0] + "/" + parts[2]
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, `{"code":400}`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.objs[key]
	if !ok {
		http.Error(w, `{"code":404}`, http.StatusNotFound)
		return
	}
	if s.ConflictNext > 0 {
		s.ConflictNext--
		http.Error(w, `{"code":409,"reason":"Conflict"}`, http.StatusConflict)
		return
	}
	inRV := in["metadata"].(map[string]any)["resourceVersion"]
	if inRV != cur["metadata"].(map[string]any)["resourceVersion"] {
		http.Error(w, `{"code":409,"reason":"Conflict"}`, http.StatusConflict)
		return
	}
	if terminal(cur) {
		http.Error(w, fmt.Sprintf(`{"code":422,"message":"%s is already answered"}`, key), http.StatusUnprocessableEntity)
		return
	}
	if msg := validateIssued(cur, in["status"]); msg != "" {
		http.Error(w, fmt.Sprintf(`{"code":422,"message":%q}`, msg), http.StatusUnprocessableEntity)
		return
	}
	s.rv++
	cur["status"] = in["status"]
	cur["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(s.rv)
	s.updates++
	s.notify("MODIFIED", cur)
	_ = json.NewEncoder(w).Encode(cur)
}

func terminal(o map[string]any) bool {
	st, _ := o["status"].(map[string]any)
	conds, _ := st["conditions"].([]any)
	for _, c := range conds {
		switch c.(map[string]any)["type"] {
		case "Issued", "Denied", "Failed":
			return true
		}
	}
	return false
}

// validateIssued applies the rules kube-apiserver applies to an issued pod
// certificate that the signer can get wrong: the leaf must parse, the status
// times must equal the leaf's, and notAfter - notBefore must lie between one
// hour and the request's maxExpirationSeconds. The first deployment broke
// the last rule and every write was refused; a fake that accepted it is how
// the tests stayed green.
func validateIssued(cur map[string]any, status any) string {
	st, _ := status.(map[string]any)
	chain, _ := st["certificateChain"].(string)
	if chain == "" {
		return ""
	}
	blk, _ := pem.Decode([]byte(chain))
	if blk == nil {
		return "certificateChain: no PEM block"
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "certificateChain: " + err.Error()
	}
	for field, want := range map[string]string{"notBefore": leaf.NotBefore.UTC().Format("2006-01-02T15:04:05Z"), "notAfter": leaf.NotAfter.UTC().Format("2006-01-02T15:04:05Z")} {
		if got, _ := st[field].(string); got != want {
			return fmt.Sprintf("status.%s %q does not match the leaf (%s)", field, got, want)
		}
	}
	d := leaf.NotAfter.Sub(leaf.NotBefore)
	spec, _ := cur["spec"].(map[string]any)
	maxExp, _ := spec["maxExpirationSeconds"].(float64)
	if maxExp == 0 {
		maxExp = 86400
	}
	if d.Seconds() > maxExp {
		return fmt.Sprintf("certificate lifetime %s exceeds maxExpirationSeconds %v", d, maxExp)
	}
	if d.Hours() < 1 {
		return fmt.Sprintf("certificate lifetime %s is below one hour", d)
	}
	return ""
}
