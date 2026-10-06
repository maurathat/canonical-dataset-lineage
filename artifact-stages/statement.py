"""Signed publication for dataset.v1 (Town proposal v0.3, section 2).

A Signed Statement is a COSE_Sign1 (RFC 9052) in Full-Content Mode with EdDSA (Ed25519), a
protected content type of application/json, a key id, and CWT claims (header 15, RFC 9597)
carrying iss (the owner) and sub (the derived identifier).

verify_publication() reports signature validity, issuer authentication, content binding and
owner binding as four separate results. It never collapses them into one pass.

Scope: Lab model. Keys are Ed25519 and resolved through an explicit registry (agent -> public
key). This is not interoperability-tested against another SCITT implementation.
"""
from __future__ import annotations

import hashlib
import io
from collections.abc import Mapping

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from canon import Reject, _identifier, _transform

ALG, CONTENT_TYPE, KID, CWT_CLAIMS = 1, 3, 4, 15
ISS, SUB = 1, 2
EDDSA = -8
COSE_SIGN1_TAG = 18
MEDIA_TYPE = "application/json"


class Malformed(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Key:
    """An Ed25519 key from a 32-byte seed."""

    def __init__(self, seed: bytes):
        self._sk = Ed25519PrivateKey.from_private_bytes(seed)
        self.public = self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.kid = kid_of(self.public)

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)


def kid_of(public: bytes) -> bytes:
    return hashlib.sha256(public).digest()[:8]


def _sig_structure(protected: bytes, payload: bytes) -> bytes:
    return cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)


def sign_statement(key: Key, iss: str, sub: str, payload: bytes, *, kid: bytes | None = None,
                   alg: int = EDDSA) -> bytes:
    """Build a Signed Statement. No policy is applied here; see publish()."""
    protected = cbor2.dumps({ALG: alg, CONTENT_TYPE: MEDIA_TYPE, KID: kid or key.kid,
                             CWT_CLAIMS: {ISS: iss, SUB: sub}}, canonical=True)
    signature = key.sign(_sig_structure(protected, payload))
    return cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, [protected, {}, payload, signature]), canonical=True)


def publish(key: Key, agent: str, raw: bytes) -> bytes:
    """Publish a dataset as `agent`. Raises Reject with a typed reason.

    OWNER_MISMATCH is the owner-substitution control: the declared owner must be the
    issuing agent.
    """
    payload = _transform(raw)
    if payload["owner"] != agent:
        raise Reject("OWNER_MISMATCH")
    return sign_statement(key, agent, _identifier(payload), raw)


def decode(statement: bytes) -> dict:
    """Strictly decode a Signed Statement. Raises Malformed(reason)."""
    try:
        stream = io.BytesIO(statement)
        item = cbor2.CBORDecoder(stream).decode()
        trailing = stream.read(1)
    except Exception:
        raise Malformed("NOT_CBOR")
    if trailing:
        raise Malformed("TRAILING_BYTES")
    if not (isinstance(item, cbor2.CBORTag) and item.tag == COSE_SIGN1_TAG
            and isinstance(item.value, (list, tuple)) and len(item.value) == 4):
        raise Malformed("NOT_COSE_SIGN1")
    protected, unprotected, payload, signature = item.value
    if not (isinstance(protected, bytes) and isinstance(payload, bytes)
            and isinstance(signature, bytes) and isinstance(unprotected, Mapping) and len(unprotected) == 0):
        raise Malformed("NOT_COSE_SIGN1")
    try:
        header = cbor2.loads(protected)
    except Exception:
        raise Malformed("BAD_PROTECTED_HEADER")
    if not (isinstance(header, Mapping) and set(header) == {ALG, CONTENT_TYPE, KID, CWT_CLAIMS}):
        raise Malformed("BAD_PROTECTED_HEADER")
    if header[ALG] != EDDSA:
        raise Malformed("UNSUPPORTED_ALG")
    if header[CONTENT_TYPE] != MEDIA_TYPE:
        raise Malformed("UNSUPPORTED_CONTENT_TYPE")
    claims = header[CWT_CLAIMS]
    if not (isinstance(header[KID], bytes) and isinstance(claims, Mapping) and set(claims) == {ISS, SUB}
            and isinstance(claims[ISS], str) and isinstance(claims[SUB], str)):
        raise Malformed("BAD_PROTECTED_HEADER")
    if len(signature) != 64:
        raise Malformed("BAD_SIGNATURE_LENGTH")
    return {"protected": protected, "kid": header[KID], "iss": claims[ISS], "sub": claims[SUB],
            "payload": payload, "signature": signature}


def verify_statement(statement: bytes, registry: dict[str, bytes]) -> dict:
    """Signature validity and issuer authentication, reported separately.

    registry maps an agent name to its 32-byte Ed25519 public key.
    signature_valid: the signature verifies under the registered key named by kid.
    issuer_authenticated: that key is the one registered to iss.
    """
    try:
        s = decode(statement)
    except Malformed as m:
        return {"well_formed": False, "reason": m.reason}
    by_kid = {kid_of(pub): pub for pub in registry.values()}
    public = by_kid.get(s["kid"])
    signature_valid = False
    if public is not None:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(
                s["signature"], _sig_structure(s["protected"], s["payload"]))
            signature_valid = True
        except InvalidSignature:
            pass
    return {"well_formed": True, "iss": s["iss"], "sub": s["sub"], "payload": s["payload"],
            "signature_valid": signature_valid,
            "issuer_authenticated": signature_valid and registry.get(s["iss"]) == public}


def verify_publication(statement: bytes, registry: dict[str, bytes]) -> dict:
    """Verify a dataset publication. Four separate results, never one collapsed pass."""
    v = verify_statement(statement, registry)
    if not v["well_formed"]:
        return v
    out = {"well_formed": True, "iss": v["iss"], "sub": v["sub"],
           "signature_valid": v["signature_valid"], "issuer_authenticated": v["issuer_authenticated"]}
    try:
        payload = _transform(v["payload"])
    except Reject as r:
        out.update(payload_reject=r.reason, content_binding=False, owner_binding=False)
        return out
    out["identifier"] = _identifier(payload)
    out["content_binding"] = out["identifier"] == v["sub"]
    out["owner_binding"] = payload["owner"] == v["iss"]
    return out


def publication_passes(result: dict) -> bool:
    return bool(result.get("well_formed") and result["signature_valid"] and result["issuer_authenticated"]
                and result["content_binding"] and result["owner_binding"])
