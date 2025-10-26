#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Minimal offline verifier for AI Trust receipts."""
import argparse, base64, json, struct, hashlib, sys, unicodedata
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import validate, ValidationError

SCHEMA = json.loads(r'''{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://example.com/ai-trust/receipt.schema.json","title":"AI Trust Receipt","type":"object","additionalProperties":false,"required":["schema_version","issued_at","nonce","alg","hash_alg","kid","task_hash","model_hash","input_commitment","output_commitment","policies","costs","canonical_hash","signature","transparency"],"properties":{"schema_version":{"$ref":"#/$defs/schema_version"},"issued_at":{"$ref":"#/$defs/issued_at"},"nonce":{"$ref":"#/$defs/nonce"},"alg":{"$ref":"#/$defs/alg"},"hash_alg":{"$ref":"#/$defs/hash_alg"},"kid":{"$ref":"#/$defs/kid"},"task_hash":{"$ref":"#/$defs/hash"},"model_hash":{"$ref":"#/$defs/hash"},"input_commitment":{"$ref":"#/$defs/hash"},"output_commitment":{"$ref":"#/$defs/hash"},"policies":{"$ref":"#/$defs/policies"},"costs":{"$ref":"#/$defs/costs"},"payload_summary":{"$ref":"#/$defs/payload_summary"},"canonical_hash":{"$ref":"#/$defs/hash"},"signature":{"$ref":"#/$defs/signature"},"transparency":{"$ref":"#/$defs/transparency"}},"$defs":{"schema_version":{"type":"string","pattern":"^\\d+\\.\\d+$","description":"Semantic version of the receipt schema"},"issued_at":{"type":"string","pattern":"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$","description":"Timestamp in ISO 8601 UTC with milliseconds"},"nonce":{"type":"string","pattern":"^[A-Za-z0-9_-]{22,24}$","description":"128-bit random nonce encoded with base64url"},"alg":{"type":"string","enum":["Ed25519"],"description":"Signature algorithm"},"hash_alg":{"type":"string","enum":["SHA-256"],"description":"Hash algorithm"},"kid":{"type":"string","pattern":"^[A-Fa-f0-9]{64}$|^did:key:[A-Za-z0-9:_-]+$","description":"Key identifier"},"hash":{"type":"string","pattern":"^sha256:[A-Za-z0-9_-]{43,}$","description":"SHA-256 hash encoded in base64url with prefix"},"policies":{"type":"object","required":["satisfied","relaxed"],"additionalProperties":false,"properties":{"satisfied":{"type":"array","items":{"type":"string","pattern":"^[A-Z0-9_]+$"},"default":[]},"relaxed":{"type":"array","items":{"type":"string","pattern":"^[A-Z0-9_]+$"},"default":[]}},"description":"Policy identifiers satisfied or relaxed"},"costs":{"type":"object","required":["latency_ms","energy_j"],"additionalProperties":false,"properties":{"latency_ms":{"type":"integer","minimum":0,"default":0},"energy_j":{"type":"number","minimum":0,"default":0}},"description":"Cost metrics"},"payload_summary":{"type":"string","pattern":"^[A-Za-z0-9_-]{0,88}$","description":"Optional base64url summary of prompt"},"signature":{"type":"string","pattern":"^[A-Za-z0-9_-]{86}$","description":"Ed25519 signature base64url without padding"},"transparency":{"type":"object","required":["log_id","leaf_hash","tree_size","inclusion_proof"],"additionalProperties":false,"properties":{"log_id":{"type":"string"},"leaf_hash":{"$ref":"#/$defs/hash"},"tree_size":{"type":"integer","minimum":0},"inclusion_proof":{"type":"object","required":["leaf_index","path","path_directions"],"additionalProperties":false,"properties":{"leaf_index":{"type":"integer","minimum":0},"path":{"type":"array","items":{"type":"string","pattern":"^[A-Za-z0-9_-]{43,}$"},"default":[]},"path_directions":{"type":"string","pattern":"^[LR]*$","default":""}}}},"description":"Transparency log metadata"}}}''')

DOMAIN = b"ai-trust-v1"


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=="[: (4 - len(data) % 4) % 4])


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def jcs(obj):
    if isinstance(obj, dict):
        return "{" + ",".join(f"{json.dumps(unicodedata.normalize('NFC',k),ensure_ascii=False)}:{jcs(v)}" for k, v in sorted(obj.items())) + "}"
    if isinstance(obj, list):
        return "[" + ",".join(jcs(x) for x in obj) + "]"
    if isinstance(obj, str):
        return json.dumps(unicodedata.normalize('NFC', obj), ensure_ascii=False, separators=(',',':'))
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        if obj == -0.0:
            obj = 0.0
        if obj != obj or obj in (float('inf'), float('-inf')):
            raise ValueError("invalid float")
        return json.dumps(obj, ensure_ascii=False, separators=(',',':'))
    if obj is None:
        return "null"
    raise TypeError("unsupported type")


def load_jwks(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return {k['kid']: k for k in data.get('keys', [])}


def verify(receipt, jwks, input_data=None, output_data=None):
    reasons = []
    try:
        validate(receipt, SCHEMA)
    except ValidationError as e:
        reasons.append(f"schema:{e.message}")
        return False, reasons
    payload_keys = ['schema_version','issued_at','nonce','alg','hash_alg','kid','task_hash','model_hash','input_commitment','output_commitment','policies','costs']
    payload = {k: receipt[k] for k in payload_keys}
    jcs_bytes = jcs(payload).encode()
    expected_hash = 'sha256:' + b64url_encode(hashlib.sha256(jcs_bytes).digest())
    if receipt['canonical_hash'] != expected_hash:
        reasons.append('canonical_hash')
    if input_data is not None:
        commit = 'sha256:' + b64url_encode(hashlib.sha256(jcs(input_data).encode()).digest())
        if commit != receipt['input_commitment']:
            reasons.append('input_commitment')
    if output_data is not None:
        commit = 'sha256:' + b64url_encode(hashlib.sha256(jcs(output_data).encode()).digest())
        if commit != receipt['output_commitment']:
            reasons.append('output_commitment')
    key = jwks.get(receipt['kid'])
    if not key:
        reasons.append('kid')
    else:
        ts = datetime.strptime(receipt['issued_at'], '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
        frame = DOMAIN + struct.pack('>Q', int(ts.timestamp()*1000)) + b64url_decode(receipt['nonce']) + jcs_bytes
        try:
            pub = Ed25519PublicKey.from_public_bytes(b64url_decode(key['public']))
            pub.verify(b64url_decode(receipt['signature']), frame)
        except Exception:
            reasons.append('signature')
    return len(reasons)==0, reasons


def main():
    ap = argparse.ArgumentParser(description='Pocket verifier for AI Trust receipts')
    ap.add_argument('receipt')
    ap.add_argument('--jwks', required=True)
    ap.add_argument('--input')
    ap.add_argument('--output')
    args = ap.parse_args()
    with open(args.receipt, 'r', encoding='utf-8') as f:
        receipt = json.load(f)
    jwks = load_jwks(args.jwks)
    input_data = json.load(open(args.input)) if args.input else None
    output_data = json.load(open(args.output)) if args.output else None
    ok, reasons = verify(receipt, jwks, input_data, output_data)
    result = {'valid': ok, 'reasons': reasons, 'warnings': []}
    print(json.dumps(result, indent=2))
    sys.exit(0 if ok else 2)

if __name__ == '__main__':
    main()
