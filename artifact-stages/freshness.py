"""Receipt-backed freshness for dataset.v1 (Town proposal v0.3, section 5).

A freshness statement is a Signed Statement from the dataset's owner whose payload cites the
dataset identifier as a typed reference. check_freshness() keeps three kinds of evidence apart:

    inclusion     each enumerated statement's receipt verifies against the signed head
    order         a statement's position is its verified leaf index; nothing else orders
    completeness  the enumeration accounts for every leaf 0..tree_size-1 under that head

The current freshness statement is the owner-authenticated one at the greatest verified
position. The window is measured in positions behind the head. Producer timestamps are parsed
and ignored. A `freshness` value inside a dataset is content, never evidence.

Decision where v0.3 is silent: a freshness payload may carry a `nonce`. Ed25519 signatures are
deterministic, so without one an owner's second refresh would be byte-identical to the first,
and idempotent registration would return the original position.

Scope: Lab model. The verifier is handed the head; it cannot tell a current head from an old
one. Proving the head is current needs an out-of-band source and is not evaluated here.
"""
from __future__ import annotations

import json

import rfc8785

from canon import HEX64, Reject, _admit, _fold_nfc, _identifier, _transform, reference
from statement import Key, sign_statement, verify_statement
from tlog import verify_head, verify_inclusion

KIND = "dataset-freshness"
REQUIRED = {"type", "schema_version", "dataset"}
OPTIONAL = {"nonce", "issued_at"}


def freshness_payload(dataset_identifier: str, nonce: str | None = None,
                      issued_at: str | None = None) -> bytes:
    body = {"type": KIND, "schema_version": "1", "dataset": reference(dataset_identifier)}
    if nonce is not None:
        body["nonce"] = nonce
    if issued_at is not None:
        body["issued_at"] = issued_at
    return rfc8785.dumps(body)


def refresh(key: Key, owner: str, dataset_identifier: str, nonce: str | None = None,
            issued_at: str | None = None) -> bytes:
    return sign_statement(key, owner, dataset_identifier,
                          freshness_payload(dataset_identifier, nonce, issued_at))


def cited_dataset(payload: bytes) -> str | None:
    """The dataset identifier a well-formed freshness payload cites, else None."""
    try:
        body = _fold_nfc(_admit(payload))
    except Reject:
        return None
    if not (isinstance(body, dict) and REQUIRED <= set(body) <= REQUIRED | OPTIONAL
            and body["type"] == KIND and body["schema_version"] == "1"):
        return None
    ref = body["dataset"]
    if not (isinstance(ref, dict) and ref == reference(ref.get("digest"))
            and isinstance(ref["digest"], str) and HEX64.match(ref["digest"])):
        return None
    if any(not isinstance(body[k], str) for k in OPTIONAL & set(body)):
        return None
    return ref["digest"]


def check_freshness(dataset_raw: bytes, registry: dict[str, bytes], log_public: bytes,
                    head, entries, window: int) -> dict:
    """entries: the enumeration, a list of {"statement": bytes, "receipt": {...}}."""
    try:
        payload = _transform(dataset_raw)
    except Reject as r:
        return {"state": "UNVERIFIED", "reason": "DATASET_REJECTED:" + r.reason}
    identifier, owner = _identifier(payload), payload["owner"]
    out = {"identifier": identifier, "owner": owner}

    if not verify_head(head, log_public):
        return {**out, "state": "UNVERIFIED", "reason": "BAD_HEAD"}
    size = head["tree_size"]
    out["head_size"] = size

    seen: dict[int, bytes] = {}
    for e in entries:
        receipt = e.get("receipt")
        if not (isinstance(receipt, dict) and receipt.get("tree_size") == size
                and verify_inclusion(e["statement"], receipt.get("leaf_index"), size,
                                     receipt.get("path"), head["root"])):
            return {**out, "state": "UNVERIFIED", "reason": "BAD_RECEIPT"}
        seen[receipt["leaf_index"]] = e["statement"]
    if set(seen) != set(range(size)):
        return {**out, "state": "UNVERIFIED", "reason": "INCOMPLETE_ENUMERATION"}

    counted, ignored = [], []
    for position in range(size):
        v = verify_statement(seen[position], registry)
        if not v["well_formed"] or cited_dataset(v["payload"]) != identifier or v["sub"] != identifier:
            continue
        if not v["signature_valid"]:
            ignored.append({"position": position, "reason": "BAD_SIGNATURE"})
        elif not v["issuer_authenticated"]:
            ignored.append({"position": position, "reason": "ISSUER_NOT_AUTHENTICATED"})
        elif v["iss"] != owner:
            ignored.append({"position": position, "reason": "NOT_OWNER"})
        else:
            counted.append(position)
    out.update(counted=counted, ignored=ignored)
    if not counted:
        return {**out, "state": "UNVERIFIED", "reason": "NO_OWNER_FRESHNESS_STATEMENT"}
    current = max(counted)
    age = size - 1 - current
    return {**out, "current_position": current, "age": age, "window": window,
            "state": "FRESH" if age <= window else "STALE"}


def declared_freshness_field(dataset_raw: bytes):
    """What a field-reading verifier would see. Used only to show it is not evidence."""
    try:
        content = json.loads(dataset_raw.decode("utf-8")).get("content")
    except Exception:
        return None
    return content.get("freshness") if isinstance(content, dict) else None
