# SPDX-License-Identifier: MPL-2.0
import hashlib
import random
import time
import uuid

import httpx

CODES = [
    "HATE_ABUSE",
    "SEXUAL_CONTENT",
    "PRIVACY_PII",
    "MALWARE",
    "SELF_HARM",
    "VIOLENCE",
    "IP_LEAK",
    "REGULATORY_J",
    "SAFETY_UNKNOWN",
]


def digest(s: str) -> str:
    return "sha256:" + hashlib.sha256(s.encode()).hexdigest()


def main() -> None:
    for i, rc in enumerate(CODES):
        evt = {
            "event_version": "gatekeeper.event.v1",
            "event_id": str(uuid.uuid4()),
            "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": uuid.uuid4().hex,
            "span_id": uuid.uuid4().hex[:16],
            "request": {
                "request_id": str(uuid.uuid4()),
                "session_id": "synth",
                "actor": {"role": "user", "region": "test"},
            },
            "gate": {
                "id": "pre_text_guard",
                "version": "1.2.3",
                "policy_namespace": "gatekeeper",
                "git_commit": "deadbeef",
                "model_digest": digest("guard:1.2.3"),
            },
            "model": {
                "name": "chat-large",
                "version": "2025-08-01",
                "digest": digest("chat-large:2025-08-01"),
            },
            "artifacts": {
                "input_commitment": digest(f"in{i}"),
                "output_commitment": digest(f"out{i}"),
            },
            "decision": {
                "action": "block" if i % 3 == 0 else "allow",
                "reason_code": rc,
                "rationale": "synthetic",
                "confidence": round(random.uniform(0.6, 0.99), 2),
            },
            "telemetry": {"latency_ms": random.choice([12, 18, 25, 40, 80, 160])},
        }
        httpx.post("http://localhost:8000/ingest", json=evt, timeout=5)


if __name__ == "__main__":
    main()

