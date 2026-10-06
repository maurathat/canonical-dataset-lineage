"""Lab transparency log for dataset.v1 freshness (Town proposal v0.3, section 5).

A local, append-only sequence standing in for a Transparency Service. A statement's position is
its leaf index. The log is a Merkle tree in the RFC 9162 section 2.1 construction, so each
registered statement has an inclusion proof that exposes its leaf index and the tree size, and
the current state is a signed tree head.

Scope: Lab model only.
  - Inclusion proofs are implemented and verified; consistency proofs between heads are not.
  - The signed head is Ed25519 over JCS({"root","tree_size"}), not an RFC 9162 STH structure.
  - No registration time is authenticated, so elapsed-time freshness cannot be claimed.

Decision where v0.3 is silent: registration is idempotent. Re-registering a byte-identical
statement returns its original position. Log(idempotent=False) is the negative control.
"""
from __future__ import annotations

import hashlib

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from statement import Key


def _leaf(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(entries: list[bytes]) -> bytes:
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return _leaf(entries[0])
    k = _split(len(entries))
    return _node(merkle_root(entries[:k]), merkle_root(entries[k:]))


def inclusion_path(index: int, entries: list[bytes]) -> list[bytes]:
    if len(entries) <= 1:
        return []
    k = _split(len(entries))
    if index < k:
        return inclusion_path(index, entries[:k]) + [merkle_root(entries[k:])]
    return inclusion_path(index - k, entries[k:]) + [merkle_root(entries[:k])]


def verify_inclusion(entry: bytes, leaf_index, tree_size, path, root_hex) -> bool:
    """RFC 9162 section 2.1.3.2. Arguments come from untrusted evidence; never raises."""
    try:
        if not (isinstance(leaf_index, int) and isinstance(tree_size, int)
                and not isinstance(leaf_index, bool) and not isinstance(tree_size, bool)
                and 0 <= leaf_index < tree_size and isinstance(path, list)):
            return False
        fn, sn, r = leaf_index, tree_size - 1, _leaf(entry)
        for p_hex in path:
            p = bytes.fromhex(p_hex)
            if len(p) != 32 or sn == 0:
                return False
            if fn & 1 or fn == sn:
                r = _node(p, r)
                if not fn & 1:
                    while fn and not fn & 1:
                        fn >>= 1
                        sn >>= 1
            else:
                r = _node(r, p)
            fn >>= 1
            sn >>= 1
        return sn == 0 and r.hex() == root_hex
    except (ValueError, TypeError):
        return False


def _head_message(root_hex: str, tree_size: int) -> bytes:
    return rfc8785.dumps({"root": root_hex, "tree_size": tree_size})


def verify_head(head, log_public: bytes) -> bool:
    try:
        if not (isinstance(head, dict) and set(head) == {"root", "tree_size", "signature"}
                and isinstance(head["tree_size"], int) and not isinstance(head["tree_size"], bool)
                and head["tree_size"] >= 0 and isinstance(head["root"], str)):
            return False
        Ed25519PublicKey.from_public_bytes(log_public).verify(
            bytes.fromhex(head["signature"]), _head_message(head["root"], head["tree_size"]))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class Log:
    def __init__(self, key: Key, idempotent: bool = True):
        self._key = key
        self.idempotent = idempotent
        self.entries: list[bytes] = []
        self._index: dict[bytes, int] = {}

    def register(self, statement: bytes) -> int:
        digest = hashlib.sha256(statement).digest()
        if self.idempotent and digest in self._index:
            return self._index[digest]
        self.entries.append(statement)
        self._index.setdefault(digest, len(self.entries) - 1)
        return len(self.entries) - 1

    def head(self, tree_size: int | None = None) -> dict:
        size = len(self.entries) if tree_size is None else tree_size
        root = merkle_root(self.entries[:size]).hex()
        return {"root": root, "tree_size": size,
                "signature": self._key.sign(_head_message(root, size)).hex()}

    def receipt(self, index: int, tree_size: int | None = None) -> dict:
        size = len(self.entries) if tree_size is None else tree_size
        return {"leaf_index": index, "tree_size": size,
                "path": [p.hex() for p in inclusion_path(index, self.entries[:size])]}

    def enumerate(self, tree_size: int | None = None) -> list[dict]:
        """The complete, auditable enumeration the Lab can supply: every leaf with its receipt."""
        size = len(self.entries) if tree_size is None else tree_size
        return [{"statement": self.entries[i], "receipt": self.receipt(i, size)} for i in range(size)]
