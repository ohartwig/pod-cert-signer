<!--
SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
SPDX-License-Identifier: Apache-2.0
-->

# pod-cert-signer

A signer for Kubernetes `PodCertificateRequest`s (GA in 1.37), signer name
`koh.ole-hartwig.eu/workload`. The kubelet generates each pod's key and asks
for a certificate. This signer checks the request against a default-deny
policy and signs a 24-hour leaf with a CA key that lives in AWS KMS and never
leaves it.

The design, and the reasons behind each decision, are in the handbook:
`engineering/pod-cert-signer-design.md` (development/gitlab-profile). This
README does not repeat them.

## State

| Part | State |
|---|---|
| `policy` | parse and validate the policy, default deny, name constraints enforced at parse time |
| `issuer` | decide a request, proof of possession, certificate profile, lifetime cap |
| `ca` | self-signed CA with critical name constraints (`svc`, `svc.cluster.local`, the SPIFFE trust domain) |
| `kube`, `controller` | list/watch, conditional status write, one answer per request (!2) |
| `kmssigner` | the CA key in KMS: P-256, `ECDSA_SHA_256` over `DIGEST`; wrong spec or usage refused at startup |
| `cmd/pod-cert-signer` | `run` (checks the CA certificate belongs to the KMS key before answering anything) and `init` (prints the CA for a KMS key) |
| image, deployment, KMS key | not yet |

## Checks that must be able to fail

```bash
go test ./...
go run ./tools/mutation   # every mutant must compile and be KILLED
reuse lint                # licensing; not in CI yet (see .gitlab-ci.yml)
```

`tools/mutation/mutations.json` removes one rule per entry: grant by
default, skip the DNS name check, lift the lifetime cap, accept any key type.
A mutant that stays green or does not build fails the command, and CI with it.
