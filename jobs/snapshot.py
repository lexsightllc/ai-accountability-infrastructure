# SPDX-License-Identifier: MPL-2.0
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import duckdb
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)


def main() -> None:
    events_path = Path("data/events.ndjson")
    snap_dir = Path("data/snapshots")
    snap_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    window = {"start": "1970-01-01T00:00:00Z", "end": now.isoformat()}

    con = duckdb.connect(database=":memory:")
    con.execute(
        """
        CREATE TABLE events AS
        SELECT * FROM read_json_auto(?, format='newline_delimited');
        """,
        [str(events_path)],
    )

    con.execute(
        """
        CREATE TABLE f_decisions AS
        SELECT
          gate->>'id' AS gate_id,
          gate->>'version' AS gate_version,
          decision->>'action' AS action,
          decision->>'reason_code' AS reason_code,
          CAST(telemetry->>'latency_ms' AS INTEGER) AS latency_ms,
          occurred_at
        FROM events;
        """
    )

    agg = con.execute(
        """
        SELECT gate_id, gate_version, action,
               COUNT(*) AS n,
               approx_quantile(latency_ms, 0.95) AS p95_latency_ms
        FROM f_decisions
        GROUP BY 1,2,3
        ORDER BY 1,2,3;
        """
    ).fetch_arrow_table()

    bundle = {
        "bundle_version": "gatekeeper.snapshot.v1",
        "window": window,
        "generated_at": now.isoformat(),
        "tables": {
            "decisions_by_action": agg.to_pydict(),
        },
    }

    blob = json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode()
    bundle_hash = "sha256:" + hashlib.sha256(blob).hexdigest()
    snap_file = snap_dir / f"{now.isoformat()}_{bundle_hash[7:19]}.json"
    snap_file.write_bytes(blob)

    key_path = Path("keys/snapshot_private.key")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if not key_path.exists():
        key = Ed25519PrivateKey.generate()
        key_path.write_bytes(
            key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
    priv = Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
    sig = priv.sign(blob).hex()

    receipt = {
        "receipt_version": "gatekeeper.metrics.receipt.v1",
        "bundle_hash": bundle_hash,
        "window": window,
        "generated_at": now.isoformat(),
        "signature_alg": "ed25519",
        "signature_hex": sig,
    }
    receipt_path = Path(str(snap_file) + ".receipt.json")
    receipt_path.write_text(json.dumps(receipt, indent=2))
    print(
        json.dumps({"bundle": str(snap_file), "receipt": str(receipt_path)}, indent=2)
    )


if __name__ == "__main__":
    main()

