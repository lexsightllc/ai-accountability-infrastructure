<!-- SPDX-License-Identifier: MPL-2.0 -->

# Wire Format

This document describes the canonical wire representation for AI Trust receipts.

## Canonical JSON

Receipts are canonicalized using the [JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/html/rfc8785) (JCS). Keys are sorted, strings are encoded in NFC, numbers use the shortest round-trip form, and no superfluous whitespace is included.

## Timestamps

`issued_at` values use ISO‑8601 in UTC with a trailing `Z` (e.g. `2024-01-20T12:34:56Z`).

## Signature Frame

The bytes signed for the `signature` field are constructed as:

```
FRAME = DOMAIN || ts_be64_ms || nonce_bytes || JCS(payload)
```

* `DOMAIN` is an application-specific constant.
* `ts_be64_ms` is the timestamp in milliseconds since epoch encoded as 64‑bit big‑endian.
* `nonce_bytes` is the raw 16‑byte value corresponding to the `nonce` string.
* `JCS(payload)` is the canonicalized JSON of the receipt fields excluding `signature`.

## Regex Summary

Key regular expressions from `receipt-v1.schema.json`:

* Nonce: `^[A-Za-z0-9_-]{22,24}$`
* Hash: `^sha256:[A-Za-z0-9_-]{43,}$`
* Signature: `^[A-Za-z0-9_-]{86}$`
