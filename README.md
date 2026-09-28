<!--
SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
SPDX-License-Identifier: Apache-2.0
-->

# pod-cert-signer

A signer for Kubernetes pod certificates. Kubernetes 1.37 lets a pod ask for
an X.509 certificate through a projected volume: the kubelet generates the key,
files a `PodCertificateRequest`, and mounts key and certificate into the pod.
Who answers the request is left to a signer. This is one.

It checks every request against a policy that denies by default, signs a
short-lived leaf with a CA key that lives in AWS KMS and never leaves it, and
writes the chain into the request's status. It never sees a private key,
neither the pod's nor its own.

Why it is built the way it is: [`docs/design.md`](docs/design.md).

## Requirements

- Kubernetes 1.37 or later: `PodCertificateRequest` and `ClusterTrustBundle`
  (`certificates.k8s.io/v1`).
- An AWS KMS key of spec `ECC_NIST_P256` with usage `SIGN_VERIFY`, reachable
  from the signer's pod (for example through IRSA, or any credential the AWS
  SDK's default chain finds).

## Install

The image is [`ghcr.io/ohartwig/pod-cert-signer`](https://github.com/ohartwig/pod-cert-signer/pkgs/container/pod-cert-signer),
`linux/amd64` and `linux/arm64`, signed keyless:

```sh
cosign verify ghcr.io/ohartwig/pod-cert-signer:0 \
  --certificate-identity-regexp '^https://github.com/ohartwig/pod-cert-signer/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Static Linux binaries (amd64, arm64) come with every
[release](https://github.com/ohartwig/pod-cert-signer/releases), with
`SHA256SUMS` and a detached cosign signature over it. They are built and
signed once, in the author's pipeline; the image packages the same files and
nothing is rebuilt on GitHub.

```sh
cosign verify-blob --key <public-key> --signature SHA256SUMS.sig \
  --insecure-ignore-tlog=true SHA256SUMS
sha256sum -c SHA256SUMS
```

## How a pod gets a certificate

```yaml
volumes:
  - name: tls
    projected:
      sources:
        - podCertificate:
            signerName: example.com/workload
            keyType: ECDSAP256
            keyPath: tls.key
            certificateChainPath: tls.crt
            userAnnotations:
              example.com/dns-names: api.team-a.svc,api.team-a.svc.cluster.local
        - clusterTrustBundle:
            signerName: example.com/workload
            labelSelector: {}
            path: ca.crt
```

The pod does not start until the certificate is issued. The kubelet renews it
at the policy's `refreshAt` fraction of its lifetime and replaces the files in
place; software that reads its certificate once has to be told to reload.

## Quick start

1. **KMS key and permissions.** Create a key with spec `ECC_NIST_P256`, usage
   `SIGN_VERIFY`. The signer needs `kms:GetPublicKey`, `kms:DescribeKey` and
   `kms:Sign`, the last restricted to `ECDSA_SHA_256` over a `DIGEST`:
   [`examples/iam-policy.json`](examples/iam-policy.json).
2. **CA certificate.** Once per key, with credentials for the key:

   ```bash
   KMS_KEY_ID=alias/pod-cert-signer pod-cert-signer init \
     -cn "Example workload CA" -trust-domain example.com > ca.crt
   ```

   The certificate carries critical name constraints: DNS names under `svc`
   and `svc.cluster.local`, URIs under `spiffe://<trust-domain>`, path length
   0. Review it and commit it; it is your trust anchor.

   For a CA that serves one namespace only, name its domains with
   `-dns-domain`, repeated: the namespace's service domains and the short
   service names its clients dial. Nothing of another namespace then verifies
   under it.

   ```bash
   KMS_KEY_ID=alias/pod-cert-signer-team-a pod-cert-signer init \
     -cn "team-a CA" -trust-domain example.com \
     -dns-domain team-a.svc -dns-domain team-a.svc.cluster.local \
     -dns-domain api -dns-domain db > ca.crt
   ```

   Run one signer per such CA, each with its own key, policy and signer
   name. A signer then holds one CA and can sign for its namespace only.
3. **Deploy.** [`examples/`](examples/) has the namespace, the RBAC, the policy
   ConfigMap (policy and `ca.crt`), the ClusterTrustBundle and the Deployment.
   Put the CA certificate into both the ConfigMap and the ClusterTrustBundle.
   At startup the signer checks that the CA certificate belongs to the KMS key
   and refuses to run otherwise.
4. **Grant and request.** Add a grant for the workload's ServiceAccount to the
   policy, and give the pod the volume above
   ([`examples/client.yaml`](examples/client.yaml)).

## Policy

A JSON file. Unknown keys are errors; a policy the signer cannot parse makes it
exit, so it never runs on a half-read or wrong policy.

```json
{
  "signerName": "example.com/workload",
  "trustDomain": "example.com",
  "dnsNamesAnnotation": "example.com/dns-names",
  "lifetime": "24h",
  "refreshAt": 0.66,
  "keyTypes": ["ECDSAP256", "ED25519"],
  "grants": [
    {"namespace": "team-a", "serviceAccount": "api", "usage": "server",
     "dnsNames": ["api.team-a.svc", "api.team-a.svc.cluster.local"]},
    {"namespace": "tenant-*", "serviceAccount": "agent", "usage": "client", "ou": "agent"}
  ]
}
```

| Field | Meaning |
|---|---|
| `signerName` | The signer name requests are addressed to. |
| `trustDomain` | SPIFFE trust domain of every identity (`spiffe://<trustDomain>/ns/<ns>/sa/<sa>`). A bare host name; must match the CA's URI constraint. |
| `dnsNamesAnnotation` | Domain-prefixed key of the `userAnnotations` entry through which a pod asks for DNS names (comma-separated). |
| `lifetime` | Leaf lifetime, at least `1h` (the API's floor). Capped further by the request's `maxExpirationSeconds`. |
| `refreshAt` | Fraction of the lifetime after which the kubelet renews, between `0.17` and `0.83`. |
| `keyTypes` | Key types the signer accepts: any of `RSA3072`, `RSA4096`, `ECDSAP256`, `ECDSAP384`, `ECDSAP521`, `ED25519`. |
| `grants` | Who gets what. Everything not granted is denied. |

A grant:

| Field | Meaning |
|---|---|
| `namespace` | An exact namespace, or a prefix ending in `*` (`tenant-*`). A bare `*` is rejected. An exact grant wins over a prefix. |
| `serviceAccount` | One literal ServiceAccount name. |
| `usage` | `client` (`clientAuth`), `server` (`serverAuth`) or `server-and-client` (both, for a workload that serves and dials with one identity). |
| `ou` | Optional subject OU, for servers that authorise clients by OU. |
| `dnsNames` | `server` and `server-and-client` grants only, required there: the names the ServiceAccount may claim. At startup every name is checked against the CA certificate's name constraints, and a name outside them keeps the signer down. A request for a name outside this list is denied as a whole, not trimmed. |

The signer exits when the policy file changes, so the Deployment restarts it
with the new version and a broken one shows as a crash loop.

## Certificate profile

| Field | Value |
|---|---|
| Subject | `CN=<namespace>/<serviceaccount>`, `OU=<grant.ou>` if set |
| SAN URI | `spiffe://<trustDomain>/ns/<namespace>/sa/<serviceaccount>` |
| SAN DNS | the requested names, if all of them are granted |
| Extended key usage | `clientAuth`, `serverAuth` or both, from the grant's `usage` |
| Validity | `notBefore` = now, whole seconds, minus one minute; `notAfter` = `notBefore` + min(`lifetime`, `maxExpirationSeconds`) |
| Renewal | `beginRefreshAt` = `notBefore` + `refreshAt` × lifetime |
| Serial | 128 random bits |
| Public key | from the request, after its proof of possession verifies |

A denied request gets a `Denied` condition with one of the reasons `NoGrant`,
`UnsupportedKeyType`, `DNSNameNotGranted` or `InvalidStubPKCS10Request`.

## Configuration

| Variable | Default | |
|---|---|---|
| `KMS_KEY_ID` | – (required) | Key ID, ARN or alias of the CA key |
| `POLICY_FILE` | `/etc/pod-cert-signer/policy.json` | |
| `CA_CERT_FILE` | `/etc/pod-cert-signer/ca.crt` | Must belong to the KMS key |
| `METRICS_ADDR` | `:9090` | `/metrics` and `/healthz` |

AWS credentials and region come from the SDK's default chain (`AWS_REGION`,
`AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE` for IRSA, and so on).

## Operating it

Run two replicas. The status write is conditional on the request's
`resourceVersion`, so each request is answered by exactly one of them. While
the signer is down, running pods keep their certificates until they expire;
new pods with a pod certificate wait.

`/healthz` fails when the signer has not listed requests successfully for three
minutes. `/metrics` exposes:

| Metric | |
|---|---|
| `pod_cert_signer_issued_total` | certificates written |
| `pod_cert_signer_denied_total{reason}` | requests denied |
| `pod_cert_signer_status_write_errors_total` | status writes the API refused, conflicts excluded |
| `pod_cert_signer_status_write_conflicts_total` | status writes that lost the race to the other replica (409); normal, one per request with two replicas |
| `pod_cert_signer_issue_errors_total` | transient failures before a write (KMS, parsing) |
| `pod_cert_signer_pending_requests` | unanswered requests at the last list |
| `pod_cert_signer_pending_oldest_seconds` | age of the oldest unanswered request |
| `pod_cert_signer_last_list_timestamp_seconds` | last successful list |

Alert on `pod_cert_signer_pending_oldest_seconds` above a few minutes: a request
nobody answers is a pod that does not start.

## Development

```bash
go test ./...
go run ./tools/mutation   # every mutant must compile and be KILLED
reuse lint
```

`tools/mutation/mutations.json` removes one rule per entry: grant by default,
skip the DNS name check, lift the lifetime cap, accept any key type, break three
of the API's status rules. A mutant that survives, or does not build, fails the
command. `fake/kubefake` is a Kubernetes API server for the tests that enforces
the API's time rules for `PodCertificateRequest` status updates.

## License

Apache-2.0, see [`LICENSE`](LICENSE).
