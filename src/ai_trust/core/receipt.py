# SPDX-License-Identifier: MPL-2.0
"""Receipt creation and verification."""
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from . import canonicalize
from .crypto import KeyPair
from .models import Receipt, ReceiptStatus, Signature


def create_receipt(
    data: dict[str, Any],
    key_pair: KeyPair,
    key_id: str = "default",
    metadata: Optional[dict[str, Any]] = None,
) -> Receipt:
    """Create a signed receipt for the given data."""
    if metadata is None:
        metadata = {}
    receipt_id = f"rec_{int(datetime.now(timezone.utc).timestamp() * 1000)}"
    timestamp = datetime.now(timezone.utc).timestamp()
    canonical_data = canonicalize(data).encode("utf-8")
    signature_bytes = key_pair.sign(canonical_data, timestamp=timestamp)
    return Receipt(
        id=receipt_id,
        data=data,
        signature=Signature(
            algorithm="ed25519",
            key_id=key_id,
            signature=signature_bytes.hex(),
            timestamp=datetime.fromtimestamp(timestamp, timezone.utc),
        ),
        status=ReceiptStatus.VERIFIED,
        metadata=metadata,
    )


def verify_receipt(receipt: Receipt, public_key: bytes) -> bool:
    """Verify the signature on a receipt."""
    try:
        public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        canonical_data = canonicalize(receipt.data).encode("utf-8")
        signature = bytes.fromhex(receipt.signature.signature)
        timestamp = receipt.signature.timestamp.timestamp()
        signed_data = (
            KeyPair.DOMAIN + int(timestamp).to_bytes(8, "big") + canonical_data
        )
        public_key_obj.verify(signature, signed_data)
    except Exception:
        return False
    else:
        return True
