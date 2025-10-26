<!-- SPDX-License-Identifier: MPL-2.0 -->

# AI Trust Infrastructure

**End‑to‑end verifiable AI accountability**

[![Demo](https://img.shields.io/badge/View-Demo-2ea44f)](https://claude.ai/public/artifacts/6f841464-05b3-4f27-99c8-18b752f82798)

A production‑ready framework for verifiable AI transparency and accountability. It couples cryptographic receipts, append‑only transparency logs, witness co‑signing, and gateway enforcement so that every AI response can be independently verified before it reaches users.

---

## Overview

The system issues a signed receipt alongside each model response. The receipt binds identity, inputs, model version, and the exact response bytes via SHA‑256. Receipts (or their digests) are inserted into a Merkle‑tree transparency log that produces auditable, consistent checkpoints. Independent witnesses co‑sign log tree heads to prevent split‑view. Gateways and SDKs operate in **fail‑closed** mode (Require‑Receipts): if proofs do not validate, the response is blocked.

---

## Key Features

* **Canonicalization Library** implementing deterministic JSON Canonicalization (RFC 8785 / JCS) for signature stability.
* **Receipt Schema (v0)**: versioned, extensible, with detached Ed25519 signatures and domain separation.
* **Transparency Log**: append‑only Merkle tree with inclusion and consistency proofs; signed tree heads (STH).
* **Witness Service**: fetches, verifies, and co‑signs STHs to mitigate split‑view.
* **Gateway Enforcement**: Envoy/NGINX plugins and a reference reverse proxy enforce Require‑Receipts.
* **CLI**: key lifecycle, receipt sign/verify, log submission/proofs, witness operations, and policy linting.
* **Language SDKs**: Python and TypeScript clients for easy integration.

---

## Security Model

* **Signatures**: Ed25519 (EdDSA) using constant‑time libraries; signatures encoded as base64url without padding; domain separation via the ASCII context string `AI-Receipt-v0\n` prefixed to the canonical byte stream.
* **Hashing**: SHA‑256 for all digests; hex lowercase encoding. `body_sha256` is computed over the **decoded** HTTP entity body (after Content‑Encoding) and must match the exact bytes forwarded to the application.
* **Canonical JSON**: RFC 8785 rules (sorted members, NFC strings, minimal escapes, deterministic number rendering, UTF‑8 no BOM, no NaN/Infinity).
* **Key Governance**: rotation and revocation with HSM/KMS‑backed keys; public keys published as JWKs via `/.well-known`.
* **Privacy**: no raw inputs in receipts; HMAC‑SHA‑256 commitments with tenant‑scoped salts; optional per‑field AEAD for sensitive metadata.
* **Time**: RFC 3339 UTC timestamps; receipts may carry `not_before` and `not_after` windows that verifiers enforce.

> Note: “forward secrecy” applies to key‑exchange protocols, not to signatures. Here we provide **signature durability** (past receipts remain verifiable after key rotation) and **compromise containment** (revocation prevents future trust).

---

## Project Layout

```
ai-trust/
├── ai_trust/                # Python package
│   ├── api/                 # FastAPI service endpoints (v0)
│   ├── core/                # Core libraries
│   │   ├── canonicalization/ # JSON canonicalization (RFC 8785)
│   │   ├── crypto/          # Ed25519, SHA-256, base64url
│   │   ├── models/          # Pydantic models (Receipt, STH, Proofs)
│   │   └── validation/      # JSON Schema & structural checks
│   ├── services/            # Background services
│   │   ├── gateway/         # Envoy/NGINX plugins & ref proxy
│   │   ├── log/             # Transparency log service
│   │   └── witness/         # Witness co-signing
│   └── cli/                 # aitrust CLI
├── docs/                    # Documentation & specs
├── examples/                # Minimal end-to-end examples
├── sdks/                    # Language SDKs (future work)
└── tests/                   # Unit & integration tests
```

---

## Quick Start

### Prerequisites

Python 3.10+, pip, and a modern compiler toolchain. Docker is optional for services. No OpenSSL dependency is required for Ed25519 if using PyNaCl/cryptography backends.

### Install

```bash
git clone https://github.com/yourorg/ai-trust.git
cd ai-trust
pip install -e '.[dev]'
pytest
```

### Generate Keys

```bash
python -m ai_trust.cli keys generate --output-dir ./keys \
  --alg Ed25519 --jwks-out ./public/jwks.json
```

### Start a Transparency Log (SQLite)

```bash
python -m ai_trust.services.log.server \
  --port 8000 --db-url sqlite:///transparency-log.db
```

### Sign and Submit a Receipt

```bash
python -m ai_trust.cli receipt sign \
  --key ./keys/private_key.json \
  --issuer https://api.your-org.com \
  --model-name example-llm-8k \
  --commit-sha $(git rev-parse HEAD) \
  --body-file ./response.bin \
  --out ./receipt.json

python -m ai_trust.cli log submit \
  --log http://localhost:8000 \
  --receipt ./receipt.json --out ./receipt.with-proof.json
```

### Verify a Receipt

```bash
python -m ai_trust.cli receipt verify \
  --receipt ./receipt.with-proof.json \
  --issuer https://api.your-org.com \
  --log http://localhost:8000 \
  --body-file ./response.bin
```

### Enforce in a Gateway (reference proxy)

```bash
python -m ai_trust.services.gateway.ref_proxy \
  --upstream http://localhost:9000 \
  --log http://localhost:8000 \
  --jwks https://api.your-org.com/.well-known/ai-trust/keys.json \
  --require-receipts enforce --min-profile B
```

---

## Discovery (`.well-known`)

Publish machine‑readable metadata under your issuer domain:

* `/.well-known/ai-trust/keys.json` — JWK Set of active Ed25519 public keys with `kid`, `created`, `not_before`, `not_after`, and `revocation_status`.
* `/.well-known/ai-trust/policy.json` — policy vocabulary, A/B/C profile mapping, relaxation reasons and max TTLs.
* `/.well-known/ai-trust/logs.json` — accredited log endpoints, public keys, and STH SLAs.
* `/.well-known/ai-trust/witnesses.json` — accredited witnesses and their signing keys.

---

## Receipt Schema (v0)

Required fields: `receipt_version`, `issuer`, `issued_at`, `execution_id`, `model.commit_sha256`, `output.body_sha256`, `signature.alg`, `signature.kid`, `signature.sig`. Unknown top‑level fields are rejected unless placed under `extensions` and listed in `critical_extensions`.

```jsonc
{
  "receipt_version": "0",
  "issuer": "https://api.your-org.com",
  "issued_at": "2025-08-31T23:50:14Z",
  "execution_id": "exec_9f1c2c...",
  "model": {
    "name": "example-llm-8k",
    "commit_sha256": "f0a1...",
    "policy_profile": "B"
  },
  "inputs": {
    "user_prompt_sha256": "3d4c...",
    "system_prompt_sha256": "b9aa..."
  },
  "output": {
    "body_sha256": "5f8e...",
    "media_type": "text/markdown; charset=utf-8",
    "truncated": false
  },
  "log": {
    "log_id": "log.ct.ai.example",
    "tree_size": 204857,
    "leaf_index": 204820,
    "root_sha256": "9ac1...",
    "inclusion_proof": ["aa..", "bb..", "cc.."],
    "signed_tree_head": {
      "timestamp": "2025-08-31T23:50:13Z",
      "witness_signatures": [
        {"witness": "w1.example", "sig": "MEQCIF..."},
        {"witness": "w2.example", "sig": "MEUCIQ..."}
      ]
    }
  },
  "signature": {
    "alg": "Ed25519",
    "kid": "did:web:api.your-org.com#k-2025-08",
    "sig": "tB2N6..."
  }
}
```

---

## Gateway Enforcement

Clients advertise posture via `Require-Receipts: enforce; min-profile=B; log=trusted-only`. Providers return `AI-Receipt: id=exec_…; location=/receipts/exec_…`. The gateway computes `body_sha256` over the bytes it forwards, resolves the receipt if needed, validates signature, inclusion proof against a fresh STH, witness quorum, and policy. On failure it blocks and returns `application/problem+json` with machine‑readable codes; on success it annotates:

```
AI-Receipt-Verified: true
AI-Receipt-Profile: B
AI-Log-STH-Age: 317ms
AI-Verification-Id: ver_abc123
```

---

## Assurance Profiles

* **A**: signature + body hash; no public log; for internal/prototype traffic.
* **B**: public log inclusion + asynchronous witnesses; for mainstream production.
* **C**: synchronous witness quorum, HSM keys, extended proof retention; for regulated workloads.

---

## Telemetry & Audit

Prometheus metrics for verification outcomes, latency, STH age, proof depth, witness quorum; structured audit logs with `verification_id`, `execution_id`, `issuer`, `profile`, decision, and reason; WORM storage aligned with retention policy; tracing spans for receipt fetch, STH fetch, proof verification, and policy evaluation.

---

## Performance Targets

Verification with cached keys and a fresh STH should complete under **10 ms p50** and **50 ms p99** on commodity hardware. STHs are cached with bounded TTL; verification is non‑blocking with circuit breakers and bounded concurrency.

---

## Documentation

* **Quickstart**: `docs/QUICKSTART.md`
* **API Reference**: `docs/api/README.md` (OpenAPI 3.1, `/v0` base path)
* **Deployment Guide**: `docs/deployment/README.md`
* **Security Model**: `docs/security/README.md`
* **Adoption Guide**: `docs/adoption/README.md`

---

## Contributing

We welcome contributions from AI providers, researchers, auditors, and regulators. See `CONTRIBUTING.md` for style, testing, and DCO guidance. Security issues: `security@your-org.com` (responsible disclosure policy in `SECURITY.md`).

---

## License

MIT — see `LICENSE`.
