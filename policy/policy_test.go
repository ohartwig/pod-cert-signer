// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"strings"
	"testing"

	"github.com/ohartwig/pod-cert-signer/policy"
)

const head = `"signerName": "example.com/workload", "trustDomain": "example.com", "dnsNamesAnnotation": "example.com/dns-names", "lifetime": "24h", "refreshAt": 0.66, "keyTypes": ["ECDSAP256"]`

// Every rule Parse enforces, fed its violation. A policy that fails here is a
// policy the signer refuses to run on (fail closed), so each case is also a
// statement about what can never reach production.
func TestParseRejects(t *testing.T) {
	for _, tc := range []struct{ name, doc, want string }{
		{"unknown key", `{` + head + `, "grants": [], "allowAll": true}`, "unknown field"},
		{"bare star namespace", `{` + head + `, "grants": [{"namespace": "*", "serviceAccount": "a", "usage": "client"}]}`, `bare "*"`},
		{"inner star", `{` + head + `, "grants": [{"namespace": "k*nde", "serviceAccount": "a", "usage": "client"}]}`, "last character"},
		{"star service account", `{` + head + `, "grants": [{"namespace": "a", "serviceAccount": "*", "usage": "client"}]}`, "literal name"},
		{"server without names", `{` + head + `, "grants": [{"namespace": "a", "serviceAccount": "b", "usage": "server"}]}`, "at least one dnsName"},
		{"client with names", `{` + head + `, "grants": [{"namespace": "a", "serviceAccount": "b", "usage": "client", "dnsNames": ["b.a.svc"]}]}`, "no dnsNames"},
		{"public dns name", `{` + head + `, "grants": [{"namespace": "a", "serviceAccount": "b", "usage": "server", "dnsNames": ["example.com"]}]}`, "name constraints"},
		{"bare suffix as name", `{` + head + `, "grants": [{"namespace": "a", "serviceAccount": "b", "usage": "server", "dnsNames": [".svc"]}]}`, "name constraints"},
		{"unknown usage", `{` + head + `, "grants": [{"namespace": "a", "serviceAccount": "b", "usage": "both"}]}`, "neither"},
		{"lifetime below floor", `{"signerName": "s", "trustDomain": "t.example", "dnsNamesAnnotation": "t.example/dns", "lifetime": "30m", "refreshAt": 0.66, "keyTypes": ["ECDSAP256"], "grants": []}`, "API floor"},
		{"refreshAt out of range", `{"signerName": "s", "trustDomain": "t.example", "dnsNamesAnnotation": "t.example/dns", "lifetime": "24h", "refreshAt": 1, "keyTypes": ["ECDSAP256"], "grants": []}`, "refreshAt"},
		{"refreshAt too close to the end", `{"signerName": "s", "trustDomain": "t.example", "dnsNamesAnnotation": "t.example/dns", "lifetime": "24h", "refreshAt": 0.9, "keyTypes": ["ECDSAP256"], "grants": []}`, "0.83"},
		{"unknown key type", `{"signerName": "s", "trustDomain": "t.example", "dnsNamesAnnotation": "t.example/dns", "lifetime": "24h", "refreshAt": 0.66, "keyTypes": ["DSA1024"], "grants": []}`, "unknown key type"},
		{"no key types", `{"signerName": "s", "trustDomain": "t.example", "dnsNamesAnnotation": "t.example/dns", "lifetime": "24h", "refreshAt": 0.66, "keyTypes": [], "grants": []}`, "keyTypes is empty"},
		{"no signer name", `{"trustDomain": "t.example", "dnsNamesAnnotation": "t.example/dns", "lifetime": "24h", "refreshAt": 0.66, "keyTypes": ["ED25519"], "grants": []}`, "signerName"},
		{"trust domain with a path", `{"signerName": "s", "trustDomain": "t.example/x", "dnsNamesAnnotation": "t.example/dns", "lifetime": "24h", "refreshAt": 0.66, "keyTypes": ["ED25519"], "grants": []}`, "bare host name"},
		{"annotation without domain", `{"signerName": "s", "trustDomain": "t.example", "dnsNamesAnnotation": "dns-names", "lifetime": "24h", "refreshAt": 0.66, "keyTypes": ["ED25519"], "grants": []}`, "domain-prefixed"},
		{"trailing data", `{` + head + `, "grants": []} {}`, "trailing"},
	} {
		_, err := policy.Parse([]byte(tc.doc))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want an error containing %q, got %v", tc.name, tc.want, err)
		}
	}
}

// An exact namespace wins over a prefix grant for the same ServiceAccount,
// whatever the order in the file.
func TestLookupPrefersTheExactNamespace(t *testing.T) {
	p, err := policy.Parse([]byte(`{` + head + `, "grants": [
	  {"namespace": "tenant-*", "serviceAccount": "agent", "usage": "client", "ou": "family"},
	  {"namespace": "tenant-a", "serviceAccount": "agent", "usage": "client", "ou": "exact"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ns, wantOU string }{
		{"tenant-a", "exact"},
		{"tenant-b", "family"},
		{"tenantb", ""},
		{"other", ""},
	} {
		g := p.Lookup(tc.ns, "agent")
		got := ""
		if g != nil {
			got = g.OU
		}
		if got != tc.wantOU {
			t.Errorf("%s: got grant %q, want %q", tc.ns, got, tc.wantOU)
		}
	}
}
