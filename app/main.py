# SPDX-License-Identifier: MPL-2.0
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from jsonschema import ValidationError, validate
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from prometheus_client import Counter, Histogram, make_asgi_app

SCHEMA = json.loads(Path("schemas/gatekeeper.event.v1.json").read_text())
EVENTS_LOG = Path("data/events.ndjson")
EVENTS_LOG.parent.mkdir(parents=True, exist_ok=True)

APP = FastAPI(title="Gatekeeper Metrics Ingest")
tracer = trace.get_tracer("gatekeeper.ingest")

REQS = Counter(
    "gk_requests_total", "events by action", ["action", "gate_id"]
)
LAT = Histogram(
    "gk_decision_latency_ms",
    "decision latency ms",
    buckets=(5, 10, 20, 50, 100, 200, 500, 1000, 2000),
)


@APP.post("/ingest")
async def ingest(evt: dict, req: Request):
    t0 = time.perf_counter()
    with tracer.start_as_current_span("ingest") as span:
        try:
            validate(instance=evt, schema=SCHEMA)
        except ValidationError as e:
            span.set_status(Status(StatusCode.ERROR, str(e)))
            raise HTTPException(
                status_code=400, detail=f"schema_error: {e.message}"
            ) from e

        if evt["decision"]["reason_code"].upper() == "MISC":
            raise HTTPException(status_code=422, detail="reason_code MISC is forbidden")

        canon = json.dumps(evt, separators=(",", ":"), sort_keys=True).encode()
        evt_hash = "sha256:" + hashlib.sha256(canon).hexdigest()

        span.set_attributes(
            {
                "gate.id": evt["gate"]["id"],
                "gate.version": evt["gate"]["version"],
                "decision.action": evt["decision"]["action"],
                "decision.reason_code": evt["decision"]["reason_code"],
                "request.id": evt["request"]["request_id"],
                "event.hash": evt_hash,
            }
        )

        with EVENTS_LOG.open("ab") as f:
            f.write(canon + b"\n")

        LAT.observe(evt["telemetry"]["latency_ms"])
        REQS.labels(evt["decision"]["action"], evt["gate"]["id"]).inc()

        span.set_status(Status(StatusCode.OK))
        return {
            "ok": True,
            "event_hash": evt_hash,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_ms": int((time.perf_counter() - t0) * 1000),
        }


APP.mount("/metrics", make_asgi_app())

