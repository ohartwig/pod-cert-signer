<!--
SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
SPDX-License-Identifier: Apache-2.0
-->

# Design

The decisions behind pod-cert-signer, and what was rejected. The README says
how to use it; this says why it looks the way it does.

## What it replaces

Services inside a cluster often authenticate with shared secrets: a password
or API key that has to exist twice, once at the client and once at the server.
When the two copies drift, nothing fails loudly. A client gets 401 or 403, and
depending on the software it keeps serving without protection, exits, or
silently reports nothing. Pod certificates remove the second copy: the server
trusts a CA, and the client proves who it is with a certificate only the
kubelet on its node ever held the key for.

## Decisions

### 1. One CA key in AWS KMS

`ECC_NIST_P256`, usage `SIGN_VERIFY`, signatures `ECDSA_SHA_256` with
`MessageType: DIGEST`. The key cannot be exported, and every signature is an
API call that is logged. Go's `crypto.Signer` hands the signer a digest, which
maps one-to-one onto `Sign` with `DIGEST`, so the KMS signer is a small
`crypto.Signer` implementation and nothing else in the code knows about KMS.

*Rejected:* the CA key in a Kubernetes Secret, which is exactly the kind of
secret this is meant to remove.

### 2. Name constraints on the CA

The CA certificate permits DNS names under `svc` and `svc.cluster.local` and
URIs in the trust domain, marked critical, with path length 0. Even a signer
whose policy check was bypassed cannot mint a certificate for a public name
that a constraint-aware client would accept. The policy parser rejects grants
for names outside these constraints, so the two can never disagree.

### 3. A single tier

No intermediate. With leaves that live a day, an intermediate buys little and
doubles the keys to manage. A CA rotation is an overlap: a new key and CA
certificate, both CAs in the ClusterTrustBundle for longer than one leaf
lifetime, then the old one removed.

### 4. The Kubernetes API over `net/http`

The signer needs to list and watch requests and update their status. client-go
would bring dozens of modules for that into the most privileged component, so
the API client is a few hundred lines on the standard library. The tests use a
fake API server that speaks the watch protocol and enforces the API's time
rules for status updates (below).

### 5. AWS through `aws-sdk-go-v2`

The credential chain (web identity, STS, request signing) is authentication
code. Writing it by hand would save modules and cost trust, so the SDK is used
for config and KMS only.

### 6. The policy is a file, and it denies by default

The policy is mounted from a ConfigMap, so a change is a reviewed commit in
whatever repository deploys it. Anything not granted is denied, unknown keys
are errors, and a policy that does not parse stops the signer. When the file
changes, the signer exits and is restarted with the new version instead of
reloading in place.

*Rejected:* grants as annotations on ServiceAccounts, which would make
identities self-service for anyone who can edit a namespace.

### 7. Two replicas, no leader election

Status updates are conditional on the request's `resourceVersion`. When two
replicas answer the same request, one write succeeds and the other gets a
conflict, so a request is never answered twice. Two replicas keep new pods
starting while one is being replaced.

### 8. Classical signatures, on purpose

Leaf and CA signatures are ECDSA P-256. What a future quantum computer
threatens *retroactively* is confidentiality, and that depends on the TLS key
exchange between the parties, not on the certificate. Signatures only need to
become quantum-safe once forging them is possible, and with one-day leaves the
switch can be made then. The `PodCertificateRequest` API accepts RSA, ECDSA and
Ed25519 subject keys only, so post-quantum leaf keys are not possible today
anyway. When verifiers support ML-DSA in X.509, a second CA can be added next
to the first (decision 3) without a design change.

## The API's rules for status updates

The API server validates the status a signer writes, and rejects it if:

- `notBefore` and `notAfter` do not equal the values in the leaf certificate,
  to the second;
- `notBefore` lies more than five minutes before the server's clock;
- the lifetime is below one hour or above the request's `maxExpirationSeconds`
  (counted from `notBefore`);
- `beginRefreshAt` is less than ten minutes after `notBefore` or less than ten
  minutes before `notAfter`;
- the leaf's public key is not the one from the request.

These rules are why the signer backdates by one minute, truncates to whole
seconds, and bounds `refreshAt` to `0.17`–`0.83`. The fake API server in
`fake/kubefake` enforces the time rules and allows at most one terminal
condition; the public key is checked by the issuer itself (proof of
possession) rather than by the fake. The three rules that broke the first releases
(whole seconds, the five-minute window, the lifetime counted from
`notBefore`) also have a mutation entry each.

## What it does not do

- It does not create or update the ClusterTrustBundle. The bundle is created
  once by whoever deploys the signer, next to the CA certificate.
- It does not reload its policy in place (decision 6).
- It supports AWS KMS only. Another key backend needs a `crypto.Signer` for it.
