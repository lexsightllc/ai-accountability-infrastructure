# SPDX-License-Identifier: MPL-2.0
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def main() -> None:
    if len(sys.argv) != 4:
        print("usage: pocket_verify.py <bundle.json> <receipt.json> <pubkey>")
        raise SystemExit(1)

    bundle_path = Path(sys.argv[1])
    receipt_path = Path(sys.argv[2])
    pubkey_path = Path(sys.argv[3])

    blob = bundle_path.read_bytes()
    calc = "sha256:" + hashlib.sha256(blob).hexdigest()
    receipt = json.loads(receipt_path.read_text())
    assert receipt["bundle_hash"] == calc, "bundle hash mismatch"

    pub = Ed25519PublicKey.from_public_bytes(pubkey_path.read_bytes())
    pub.verify(bytes.fromhex(receipt["signature_hex"]), blob)

    data = json.loads(blob)
    assert data["bundle_version"] == "gatekeeper.snapshot.v1"

    print("OK: signature and hash verified; window:", data["window"])


if __name__ == "__main__":
    main()

