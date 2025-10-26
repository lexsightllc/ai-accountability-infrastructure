# SPDX-License-Identifier: MPL-2.0
Receipt Specification v1
========================

.. note::
   This specification is released under the `Creative Commons Zero v1.0
   Universal <https://creativecommons.org/publicdomain/zero/1.0/>`_
   license. You may freely use, modify, and distribute this document
   without attribution.

Introduction
------------
The receipt format enables offline verification of AI system outputs.
Implementations should produce structured receipts that can be verified
without network calls.

Canonicalization
----------------
Receipts MUST be canonicalized using the JSON Canonicalization Scheme
(RFC 8785). Key requirements include:

* Object keys sorted lexicographically.
* UTF-8 encoding with Unicode normalization (NFC).
* Numbers represented in the shortest form that round-trips to the same
  IEEE-754 value; non-finite values are disallowed.
* Timestamps encoded as UTC ISO-8601 strings with microsecond precision
  and a trailing ``Z``.
* The following fields are required and MUST be present before
  canonicalization:

  - ``nonce``: A unique random string per receipt.
  - ``timestamp``: Creation time as defined above.

Signature
---------
The signature is computed over the canonicalized JSON bytes. The
canonical form is hashed with SHA-256, and the hash is signed using
`Ed25519 <https://datatracker.ietf.org/doc/html/rfc8032>`_.

Signatures MUST be encoded using URL-safe base64 without padding. The
receipt structure SHOULD include a ``signature`` field containing the
signature and a ``public_key`` field so verifiers can validate it
offline.

Example
-------
.. code-block:: json

   {
       "nonce": "2ec0b86b-6b7f-47c9-8fcf-4f41e2b5c21d",
       "timestamp": "2024-05-01T12:00:00.000000Z",
       "input_hash": "...",
       "output_hash": "...",
       "signature": "base64urlsafe...",
       "public_key": "base64urlsafe..."
   }

Verification
------------
To verify a receipt:

1. Remove the ``signature`` field.
2. Canonicalize the remaining structure.
3. Hash the canonical bytes with SHA-256.
4. Verify the Ed25519 signature using the provided ``public_key``.

If the signature matches, the receipt is valid and can be trusted
without contacting a remote service.
