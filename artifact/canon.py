"""dataset.v1 canonicalization pipeline (Town proposal v0.3, section 1).

dataset_id(raw: bytes) -> str   64-char lowercase hex, or raises Reject(reason).
Scope: canonical identity only. No signing, lineage traversal, or freshness.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from decimal import Decimal, InvalidOperation

import rfc8785

SAFE_INTEGER = 2**53 - 1
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MEMBERS = {"content", "owner", "schema_version", "parents", "parent", "address"}
SCHEMA_VERSION = "1"
REFERENCE_KEYS = {"type", "digest_alg", "digest"}


class Reject(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def reference(digest: str) -> dict:
    return {"type": "dataset", "digest_alg": "SHA-256", "digest": digest}


# step 1: admit and validate ----------------------------------------------------------------
def _decode(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise Reject("BOM_PRESENT")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Reject("INVALID_UTF8")


def _reject_duplicates(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise Reject("DUPLICATE_MEMBER")
        seen.add(key)
    return dict(pairs)


def _integral_number(token: str) -> int:
    try:
        value = Decimal(token)
    except InvalidOperation:
        raise Reject("MALFORMED_JSON")
    if value != value.to_integral_value():
        raise Reject("NUMBER_NOT_INTEGRAL")
    if abs(value) > SAFE_INTEGER:
        raise Reject("NUMBER_OUT_OF_RANGE")
    return int(value)


def _non_finite(_constant):
    raise Reject("NON_FINITE")


def _require_scalar_unicode(value) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise Reject("NON_SCALAR_UNICODE")
    elif isinstance(value, list):
        for item in value:
            _require_scalar_unicode(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _require_scalar_unicode(key)
            _require_scalar_unicode(item)


def _admit(raw: bytes):
    text = _decode(raw)
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicates,
                           parse_int=_integral_number, parse_float=_integral_number,
                           parse_constant=_non_finite)
    except json.JSONDecodeError:
        raise Reject("MALFORMED_JSON")
    _require_scalar_unicode(value)
    return value


# step 2: dataset transformation ------------------------------------------------------------
def _fold_nfc(value):
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_fold_nfc(item) for item in value]
    if isinstance(value, dict):
        folded = {}
        for key, item in value.items():
            name = unicodedata.normalize("NFC", key)
            if name in folded:
                raise Reject("NFC_NAME_COLLISION")
            folded[name] = _fold_nfc(item)
        return folded
    return value


def _reference_digest(ref) -> str:
    if not (isinstance(ref, dict) and set(ref) == REFERENCE_KEYS
            and ref["type"] == "dataset" and ref["digest_alg"] == "SHA-256"
            and isinstance(ref["digest"], str) and HEX64.match(ref["digest"])):
        raise Reject("MALFORMED_REFERENCE")
    return ref["digest"]


def _normalize_parents(payload: dict) -> None:
    if "parents" not in payload and "parent" not in payload:
        raise Reject("MISSING_MEMBER")
    typed = None
    if "parents" in payload:
        if not isinstance(payload["parents"], list):
            raise Reject("MALFORMED_REFERENCE")
        typed = [_reference_digest(ref) for ref in payload["parents"]]
        if len(typed) != len(set(typed)):
            raise Reject("DUPLICATE_PARENT")
    legacy = None
    if "parent" in payload:
        digest = payload.pop("parent")
        if not (isinstance(digest, str) and HEX64.match(digest)):
            raise Reject("MALFORMED_REFERENCE")
        legacy = [digest]
    if typed is not None and legacy is not None and set(typed) != set(legacy):
        raise Reject("PARENT_SPELLING_CONFLICT")
    payload["parents"] = [reference(d) for d in sorted(typed if typed is not None else legacy)]


def _require_shape(payload) -> None:
    if not isinstance(payload, dict):
        raise Reject("NOT_AN_OBJECT")
    if set(payload) - MEMBERS:
        raise Reject("UNKNOWN_MEMBER")
    if "content" not in payload:
        raise Reject("CONTENT_LESS")
    if "owner" not in payload or "schema_version" not in payload:
        raise Reject("MISSING_MEMBER")
    if not (isinstance(payload["owner"], str) and payload["owner"]):
        raise Reject("INVALID_OWNER")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise Reject("UNSUPPORTED_SCHEMA_VERSION")
    if "address" in payload and not (isinstance(payload["address"], str) and HEX64.match(payload["address"])):
        raise Reject("MALFORMED_ADDRESS")
    _normalize_parents(payload)


def _transform(raw: bytes) -> dict:
    payload = _fold_nfc(_admit(raw))
    _require_shape(payload)
    return payload


# steps 3-4: exclusion and CPB jcs ----------------------------------------------------------
def _identifier(payload: dict) -> str:
    preimage = {k: v for k, v in payload.items() if k != "address"}
    return hashlib.sha256(rfc8785.dumps(preimage)).hexdigest()


def dataset_id(raw: bytes) -> str:
    return _identifier(_transform(raw))


def carried_address_matches(raw: bytes) -> bool | None:
    """None if no address is carried; otherwise whether it equals the recomputed identifier."""
    payload = _transform(raw)
    if "address" not in payload:
        return None
    return payload["address"] == _identifier(payload)
