"""Lineage traversal for dataset.v1 (Town proposal v0.3, section 4).

traverse(root_raw, store) walks the canonical `parents` set from a root dataset. `store` maps a
64-hex digest to the bytes a resolver returned for it. Every edge gets one state:

    Verified    parent obtained and its recomputed identifier matches the reference
    Failed      parent obtained but its recomputed identifier differs, or it is inadmissible
    Unresolved  parent cannot be obtained
    Malformed   the reference itself is structurally invalid
    Cyclic      the reference points at a dataset already on the current path

Only Verified counts toward a pass. Edges come only from the canonical parents set: a
reference-shaped value inside `content` never creates an edge.

Decision where v0.3 is silent: traversal continues through a Failed parent for diagnosis only.
Under honest content addressing a cycle cannot verify, so a cycle is always reached through at
least one Failed edge; stopping at the first Failed edge would make Cyclic unreachable.
Nothing found below a Failed edge can make the walk pass.
"""
from __future__ import annotations

import json

from canon import HEX64, REFERENCE_KEYS, Reject, _identifier, _transform


def _is_reference(ref) -> bool:
    return (isinstance(ref, dict) and set(ref) == REFERENCE_KEYS and ref["type"] == "dataset"
            and ref["digest_alg"] == "SHA-256" and isinstance(ref["digest"], str)
            and bool(HEX64.match(ref["digest"])))


def _lenient_parents(raw: bytes):
    """Best-effort parent entries of inadmissible bytes, for reporting Malformed edges only."""
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception:
        return []
    if not isinstance(value, dict):
        return []
    entries = value.get("parents", [])
    entries = list(entries) if isinstance(entries, list) else [entries]
    if "parent" in value:
        legacy = value["parent"]
        entries.append({"type": "dataset", "digest_alg": "SHA-256", "digest": legacy}
                       if isinstance(legacy, str) else legacy)
    return entries


def _inspect(raw: bytes):
    """(identifier or None, reject reason or None, parent digests, malformed entry count)."""
    try:
        payload = _transform(raw)
    except Reject as r:
        entries = _lenient_parents(raw)
        good = sorted({e["digest"] for e in entries if _is_reference(e)})
        return None, r.reason, good, sum(1 for e in entries if not _is_reference(e))
    return _identifier(payload), None, [ref["digest"] for ref in payload["parents"]], 0


def traverse(root_raw: bytes, store: dict[str, bytes]) -> dict:
    edges: list[dict] = []
    expanded: set[str] = set()

    def walk(node: str, parents: list[str], malformed: int, path: tuple[str, ...]) -> None:
        for _ in range(malformed):
            edges.append({"from": node, "to": None, "state": "Malformed"})
        for digest in parents:
            edge = {"from": node, "to": digest}
            edges.append(edge)
            if digest in path:
                edge["state"] = "Cyclic"
                continue
            raw = store.get(digest)
            if raw is None:
                edge["state"] = "Unresolved"
                continue
            identifier, reason, grand, bad = _inspect(raw)
            if reason is not None:
                edge.update(state="Failed", detail="REJECT:" + reason)
            elif identifier != digest:
                edge.update(state="Failed", detail="IDENTIFIER_MISMATCH")
            else:
                edge["state"] = "Verified"
            if digest not in expanded:
                expanded.add(digest)
                walk(digest, grand, bad, path + (digest,))

    identifier, reason, parents, bad = _inspect(root_raw)
    if reason is not None:
        root = {"state": "Rejected", "detail": reason}
        node = "<root>"
    else:
        root = {"state": "Admitted", "identifier": identifier}
        node = identifier
    expanded.add(node)
    walk(node, parents, bad, (node,))
    states: dict[str, int] = {}
    for e in edges:
        states[e["state"]] = states.get(e["state"], 0) + 1
    passed = root["state"] == "Admitted" and all(e["state"] == "Verified" for e in edges)
    return {"root": root, "edges": edges, "states": states, "pass": passed}
