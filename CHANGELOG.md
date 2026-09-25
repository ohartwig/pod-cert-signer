## [0.1.1](https://git.ole-hartwig.eu/devops/pod-cert-signer/compare/v0.1.0...v0.1.1) (2026-09-25)

### :bug: Fixes

* certificates the API accepts, and status failures that are logged ([feb5d49](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/feb5d498d1f06f5ca2131a91b3d876ff4a06e27b))

## [0.1.0] (2026-09-25)

### :sparkles: Features

* the CA key in KMS, and the command that runs it all ([ef12310](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/ef123106609f3462eaadb23b9b72d23ce8726c71))
* Kubernetes API, controller and a fake API server that speaks the protocol ([0bf1d2d](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/0bf1d2da3e6b501705ea3b0d387ec13a09b69eb9))
* trust domain and DNS-name annotation come from the policy ([c20aec6](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/c20aec6783af6c629db54824d407d0d4b2af97b2))
* policy, issuer and CA - the part that decides who is who ([8a72bbf](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/8a72bbf37d522e30ebe8e5e3d4dd445f0b10def1))

### :bug: Fixes

* **ci:** name the non-release paths yasrt needs for product custom ([8ec2c32](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/8ec2c324ce96f5a02301a2717c19acea7240260c))

### :repeat: Continuous Integrations

* **deps:** update registry.ole-hartwig.eu/devops/images/curl:8.21 docker digest to a913997 ([1d09981](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/1d0998177c346a1eef72690a7799259fa594efd9))
* release linux binaries, signed, before the tag ([720d19d](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/720d19da65570d4c1a676f6dc96bfdfb7aa477f9))
* **deps:** pin registry.ole-hartwig.eu/devops/images/golang docker tag to 9940fe5 ([e41bcf3](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/e41bcf3f68f6a41ca0254b8934b91ac90fe327f8))
* take the REUSE job out until a multi-arch reuse image exists ([b497166](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/b497166071892ebc0a99394845b5ab9285cbafec))
* the REUSE job actually runs and can fail; test:mutation names its image ([7e06835](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/7e06835285369a5cc88b8f7e6b0234313bd00b61))

### :repeat: Chores

* repository baseline from devops/repo-templates, Apache-2.0 ([8247a47](https://git.ole-hartwig.eu/devops/pod-cert-signer/commit/8247a4768077b790f9d6bfa0614ca26d67c3e0f1))
