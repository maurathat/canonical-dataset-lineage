"""Build vectors.json for the signed-publication, lineage and freshness stages.

Every input is exact bytes (base64) plus the evidence a verifier would be handed. Expected
outcomes are pinned from this implementation: they guard against regressions and give an
independent implementation a fixed target; they are not independent evidence. Each vector also
states the outcome it was written to produce (`want`), and the build fails if the
implementation disagrees, so a pinned result is never just "whatever the code returned".

Keys are derived from public labels. They are test keys and protect nothing.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unicodedata

import cbor2

from canon import Reject, dataset_id, reference
from freshness import check_freshness, declared_freshness_field, refresh
from lineage import traverse
from statement import Key, publication_passes, publish, sign_statement, verify_publication
from tlog import Log

AGENTS = ["supplier-1", "supplier-2", "manufacturer", "auditor", "mallory"]
SEED = {name: hashlib.sha256(("dataset.v1 lab key: " + name).encode()).digest()
        for name in AGENTS + ["lab-log"]}
KEY = {name: Key(seed) for name, seed in SEED.items()}
REGISTRY = {name: KEY[name].public for name in AGENTS}
LOG_PUBLIC = KEY["lab-log"].public

b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
E_NFD = unicodedata.normalize("NFD", "é")


def ds(owner: str, content: str, parents: list[str] = (), extra: str = "") -> bytes:
    refs = ",".join(json.dumps(reference(d), separators=(",", ":")) for d in parents)
    return ('{"owner":"%s","schema_version":"1","parents":[%s],"content":%s%s}'
            % (owner, refs, content, extra)).encode()


PART_A = ds("supplier-1", '{"part":"bracket","mass_g":120,"finish":"Café brown"}')
PART_B = ds("supplier-2", '{"part":"bolt","mass_g":8}')
A, B = dataset_id(PART_A), dataset_id(PART_B)
ASSEMBLY = ds("manufacturer", '{"assembly":"mount","count":4}', [A, B])
ASM = dataset_id(ASSEMBLY)
PLAN = ds("manufacturer", '{"plan":"line-2","shift":1}', [ASM])
PART_A_REENC = ('{"content":{"finish":"Caf%s brown","mass_g":120.0,"part":"bracket"},'
                '"parents":[],"schema_version":"1","owner":"supplier-1"}' % E_NFD).encode()
assert dataset_id(PART_A_REENC) == A

vectors: list[dict] = []


def add(vid, stage, note, input_, expect, want):
    for k, v in want.items():
        assert expect.get(k) == v, f"{vid}: wanted {k}={v!r}, implementation gave {expect.get(k)!r}"
    vectors.append({"id": vid, "stage": stage, "note": note, "input": input_, "expect": expect, "want": want})


# --- signed publication ---------------------------------------------------------------------
def pub(vid, note, statement, want):
    result = verify_publication(statement, REGISTRY)
    result["pass"] = publication_passes(result)
    add(vid, "signed_publication", note, {"statement_b64": b64(statement)}, result, want)


def pub_attempt(vid, note, agent, raw, want):
    try:
        expect = {"published": True, "identifier": verify_publication(publish(KEY[agent], agent, raw), REGISTRY)["identifier"]}
    except Reject as r:
        expect = {"published": False, "reject": r.reason}
    add(vid, "signed_publication", note, {"publish": {"agent": agent, "payload_b64": b64(raw)}}, expect, want)


honest = publish(KEY["supplier-1"], "supplier-1", PART_A)
pub("pub-honest", "owner publishes its own dataset", honest, {"pass": True, "identifier": A})
pub("pub-reencoded", "owner publishes a re-encoding; same identifier, different statement bytes",
    publish(KEY["supplier-1"], "supplier-1", PART_A_REENC), {"pass": True, "identifier": A})
pub("pub-derived", "manufacturer publishes a dataset with two parents",
    publish(KEY["manufacturer"], "manufacturer", ASSEMBLY), {"pass": True, "identifier": ASM})
pub_attempt("pub-accept", "publication by the declared owner is accepted", "supplier-1", PART_A,
            {"published": True})
pub_attempt("pub-owner-substitution", "mallory publishes a dataset declaring supplier-1 as owner",
            "mallory", PART_A, {"published": False, "reject": "OWNER_MISMATCH"})
pub_attempt("pub-inadmissible", "publication of a content-less payload",
            "supplier-1", b'{"owner":"supplier-1","schema_version":"1","parents":[]}',
            {"published": False, "reject": "CONTENT_LESS"})
pub("pub-forged-owner", "mallory signs as herself over a payload that names supplier-1 as owner",
    sign_statement(KEY["mallory"], "mallory", A, PART_A),
    {"pass": False, "signature_valid": True, "issuer_authenticated": True, "content_binding": True,
     "owner_binding": False})
pub("pub-wrong-issuer", "mallory's key and key id, iss claims supplier-1",
    sign_statement(KEY["mallory"], "supplier-1", A, PART_A),
    {"pass": False, "signature_valid": True, "issuer_authenticated": False})
pub("pub-stolen-kid", "mallory signs but names supplier-1's key id",
    sign_statement(KEY["mallory"], "supplier-1", A, PART_A, kid=KEY["supplier-1"].kid),
    {"pass": False, "signature_valid": False, "issuer_authenticated": False})
pub("pub-unknown-key", "signed by a key that is not in the registry",
    sign_statement(Key(hashlib.sha256(b"unregistered").digest()), "supplier-1", A, PART_A),
    {"pass": False, "signature_valid": False})
parts = list(cbor2.loads(honest).value)
parts[2] = PART_A.replace(b"120", b"121")
pub("pub-tampered-payload", "payload changed after signing",
    cbor2.dumps(cbor2.CBORTag(18, [parts[0], {}, parts[2], parts[3]]), canonical=True),
    {"pass": False, "signature_valid": False, "content_binding": False})
pub("pub-wrong-sub", "validly signed, but sub names a different dataset",
    sign_statement(KEY["supplier-1"], "supplier-1", B, PART_A),
    {"pass": False, "signature_valid": True, "content_binding": False})
pub("pub-signed-inadmissible", "validly signed payload that the canonicalization pipeline rejects",
    sign_statement(KEY["supplier-1"], "supplier-1", A, PART_A.replace(b"120", b"120.5")),
    {"pass": False, "signature_valid": True, "payload_reject": "NUMBER_NOT_INTEGRAL"})
pub("pub-wrong-alg", "protected header declares an algorithm other than EdDSA",
    sign_statement(KEY["supplier-1"], "supplier-1", A, PART_A, alg=-7),
    {"well_formed": False, "reason": "UNSUPPORTED_ALG"})
pub("pub-truncated", "statement truncated", honest[:-10], {"well_formed": False})
pub("pub-trailing", "statement followed by extra bytes", honest + b"\x00",
    {"well_formed": False, "reason": "TRAILING_BYTES"})

# --- lineage ---------------------------------------------------------------------------------
def lin(vid, note, root, store, want, want_states=None):
    result = traverse(root, store)
    if want_states is not None:
        assert result["states"] == want_states, f"{vid}: states {result['states']}"
    add(vid, "lineage", note, {"root_b64": b64(root), "store": {d: b64(r) for d, r in store.items()}},
        result, want)


FULL = {A: PART_A, B: PART_B, ASM: ASSEMBLY}
lin("lin-honest", "assembly with two verified parents", ASSEMBLY, FULL, {"pass": True}, {"Verified": 2})
lin("lin-deep", "plan -> assembly -> parts", PLAN, FULL, {"pass": True}, {"Verified": 3})
lin("lin-no-parents", "a root dataset has no edges", PART_A, {}, {"pass": True}, {})
REPORT = ds("auditor", '{"report":"q3"}', [ASM, A])
lin("lin-diamond", "a parent reached by two paths is not a cycle", REPORT, FULL, {"pass": True},
    {"Verified": 4})
lin("lin-reencoded-parent", "parent stored in a different encoding still verifies", ASSEMBLY,
    {A: PART_A_REENC, B: PART_B}, {"pass": True}, {"Verified": 2})
LEGACY = ('{"owner":"manufacturer","schema_version":"1","parent":"%s","content":{"note":"legacy"}}' % A).encode()
lin("lin-legacy-spelling", "legacy single `parent` spelling is walked", LEGACY, FULL, {"pass": True},
    {"Verified": 1})
lin("lin-broken", "a parent cannot be obtained", ASSEMBLY, {A: PART_A}, {"pass": False},
    {"Verified": 1, "Unresolved": 1})
lin("lin-tampered", "resolver returns altered bytes for a parent", ASSEMBLY,
    {A: PART_A.replace(b"120", b"121"), B: PART_B}, {"pass": False}, {"Verified": 1, "Failed": 1})
lin("lin-inadmissible-parent", "resolver returns bytes the pipeline rejects", ASSEMBLY,
    {A: PART_A.replace(b"120", b"120.5"), B: PART_B}, {"pass": False}, {"Verified": 1, "Failed": 1})
lin("lin-deep-broken", "break two levels down", PLAN, {ASM: ASSEMBLY, A: PART_A}, {"pass": False},
    {"Verified": 2, "Unresolved": 1})
FAKE = "c" * 64
CYC_A = ds("mallory", '{"n":1}', [FAKE])
CYC_B = ds("mallory", '{"n":2}', [dataset_id(CYC_A)])
lin("lin-cyclic", "forged two-node cycle is detected and the walk terminates", CYC_A,
    {FAKE: CYC_B, dataset_id(CYC_A): CYC_A}, {"pass": False}, {"Failed": 1, "Cyclic": 1})
SELF = ds("mallory", '{"n":3}', [FAKE])
lin("lin-self-cycle", "forged self-reference", SELF, {FAKE: ds("mallory", '{"n":4}', [FAKE])},
    {"pass": False}, {"Failed": 1, "Cyclic": 1})
PHANTOM = ds("manufacturer", '{"assembly":"mount","parents":[%s],"parent":"%s"}'
             % (json.dumps(reference(B), separators=(",", ":")), B), [A])
lin("lin-phantom-in-content", "reference-shaped values inside content create no edge", PHANTOM, FULL,
    {"pass": True}, {"Verified": 1})
HINT = ds("manufacturer", '{"assembly":"mount"}', [A], ',"parent_hint":"%s"' % B)
lin("lin-phantom-top-level", "unlisted top-level parent_hint: root is rejected, not walked as an edge",
    HINT, FULL, {"pass": False})
BADREF = ('{"owner":"manufacturer","schema_version":"1","content":1,"parents":[{"type":"dataset","digest":"%s"},%s]}'
          % (B, json.dumps(reference(A), separators=(",", ":")))).encode()
lin("lin-malformed-reference", "a structurally invalid reference is reported Malformed", BADREF, FULL,
    {"pass": False}, {"Malformed": 1, "Verified": 1})

# --- freshness -------------------------------------------------------------------------------
def evidence(log: Log, size: int | None = None):
    return log.head(size), log.enumerate(size)


def fre(vid, stage, note, dataset, head, entries, window, want, extra=None):
    result = check_freshness(dataset, REGISTRY, LOG_PUBLIC, head, entries, window)
    if extra:
        result.update(extra)
    add(vid, stage, note,
        {"dataset_b64": b64(dataset), "window": window, "head": head,
         "entries": [{"statement_b64": b64(e["statement"]), "receipt": e["receipt"]} for e in entries]},
        result, want)


def new_log(idempotent=True) -> Log:
    log = Log(KEY["lab-log"], idempotent)
    log.register(publish(KEY["supplier-1"], "supplier-1", PART_A))
    log.register(publish(KEY["supplier-2"], "supplier-2", PART_B))
    return log


def filler(log: Log, n: int, tag: str):
    for i in range(n):
        log.register(refresh(KEY["supplier-2"], "supplier-2", B, nonce=f"{tag}-{i}"))


R1 = refresh(KEY["supplier-1"], "supplier-1", A, nonce="r1")
R2 = refresh(KEY["supplier-1"], "supplier-1", A, nonce="r2")
WINDOW = 3

log = new_log(); log.register(R1)
fre("fre-fresh", "freshness", "owner refresh inside the window", PART_A, *evidence(log), WINDOW,
    {"state": "FRESH", "current_position": 2})
fre("fre-fresh-reencoded", "freshness", "a re-encoded copy of the dataset is fresh under the same evidence",
    PART_A_REENC, *evidence(log), WINDOW, {"state": "FRESH", "current_position": 2})

log = new_log()
DECLARED = ds("supplier-1", '{"part":"bracket","freshness":"2099-01-01T00:00:00Z"}')
log.register(publish(KEY["supplier-1"], "supplier-1", DECLARED))
fre("fre-field-is-not-evidence", "freshness", "a freshness value in content, with no statement, is unverified",
    DECLARED, *evidence(log), WINDOW, {"state": "UNVERIFIED", "reason": "NO_OWNER_FRESHNESS_STATEMENT"})

log = new_log(); log.register(R1); filler(log, 5, "f")
fre("fre-stale", "freshness", "refresh has fallen behind the window", PART_A, *evidence(log), WINDOW,
    {"state": "STALE", "current_position": 2, "age": 5})

log.register(R2)
fre("fre-superseded", "freshness", "a later owner statement supersedes the earlier one", PART_A,
    *evidence(log), WINDOW, {"state": "FRESH", "current_position": 8, "counted": [2, 8]})

log = new_log(); log.register(R1); filler(log, 5, "f")
assert log.register(R1) == 2
fre("fre-stale-replay", "freshness", "re-registering the old statement returns its original position",
    PART_A, *evidence(log), WINDOW, {"state": "STALE", "current_position": 2})

log = new_log(); filler(log, 1, "f")
log.register(refresh(KEY["mallory"], "mallory", A, nonce="m1"))
fre("fre-non-owner", "freshness", "a non-owner's statement about the dataset does not refresh it", PART_A,
    *evidence(log), WINDOW, {"state": "UNVERIFIED", "ignored": [{"position": 3, "reason": "NOT_OWNER"}]})

log = new_log(); log.register(R1); filler(log, 5, "f")
log.register(refresh(KEY["mallory"], "supplier-1", A, nonce="m2"))
fre("fre-impostor", "freshness", "statement claims the owner as issuer but is signed by another key",
    PART_A, *evidence(log), WINDOW,
    {"state": "STALE", "current_position": 2, "ignored": [{"position": 8, "reason": "ISSUER_NOT_AUTHENTICATED"}]})

log = new_log(); log.register(R1); filler(log, 5, "f")
log.register(sign_statement(KEY["mallory"], "supplier-1", A, cbor2.loads(R1).value[2],
                            kid=KEY["supplier-1"].kid))
fre("fre-bad-signature", "freshness", "owner's key id on a signature the owner's key did not make",
    PART_A, *evidence(log), WINDOW,
    {"state": "STALE", "ignored": [{"position": 8, "reason": "BAD_SIGNATURE"}]})

log = new_log()
log.register(refresh(KEY["supplier-1"], "supplier-1", A, nonce="late-clock", issued_at="2099-01-01T00:00:00Z"))
filler(log, 5, "f")
fre("fre-future-clock", "freshness", "a far-future producer timestamp does not keep a statement fresh",
    PART_A, *evidence(log), WINDOW, {"state": "STALE", "current_position": 2})

log = new_log()
log.register(refresh(KEY["supplier-1"], "supplier-1", A, nonce="c1", issued_at="2030-01-01T00:00:00Z"))
log.register(refresh(KEY["supplier-1"], "supplier-1", A, nonce="c2", issued_at="2020-01-01T00:00:00Z"))
fre("fre-clock-order", "freshness", "order follows position; the later position carries the earlier timestamp",
    PART_A, *evidence(log), WINDOW, {"state": "FRESH", "current_position": 3, "counted": [2, 3]})

log = new_log(); log.register(refresh(KEY["supplier-2"], "supplier-2", B, nonce="b1"))
fre("fre-other-dataset", "freshness", "a refresh of a different dataset does not count", PART_A,
    *evidence(log), WINDOW, {"state": "UNVERIFIED", "counted": []})

log = new_log(); log.register(R1); filler(log, 2, "f")
head, entries = evidence(log)
fre("fre-incomplete", "freshness", "enumeration omits a leaf", PART_A, head, entries[:-1], WINDOW,
    {"state": "UNVERIFIED", "reason": "INCOMPLETE_ENUMERATION"})
bad = [dict(e, receipt=dict(e["receipt"])) for e in entries]
bad[2]["receipt"]["path"] = ["00" * 32] + bad[2]["receipt"]["path"][1:]
fre("fre-bad-receipt", "freshness", "an inclusion proof does not verify", PART_A, head, bad, WINDOW,
    {"state": "UNVERIFIED", "reason": "BAD_RECEIPT"})
moved = [dict(e, receipt=dict(e["receipt"])) for e in entries]
moved[2]["receipt"]["leaf_index"] = 4
fre("fre-moved-position", "freshness", "a receipt claims a later position than the proof supports",
    PART_A, head, moved, WINDOW, {"state": "UNVERIFIED", "reason": "BAD_RECEIPT"})
fre("fre-bad-head", "freshness", "tree head signature does not verify", PART_A,
    dict(head, tree_size=head["tree_size"] + 1), entries, WINDOW, {"state": "UNVERIFIED", "reason": "BAD_HEAD"})
fre("fre-inadmissible-dataset", "freshness", "the dataset itself is rejected", PART_A.replace(b"120", b"1.5"),
    head, entries, WINDOW, {"state": "UNVERIFIED"})

# --- controls and stated limits --------------------------------------------------------------
log = new_log(idempotent=False); log.register(R1); filler(log, 5, "f")
assert log.register(R1) == 8
fre("ctl-replay-non-idempotent-log", "controls",
    "CONTROL: on a log that appends duplicates, the stale replay restores freshness", PART_A,
    *evidence(log), WINDOW, {"state": "FRESH", "current_position": 8})

log = new_log()
log.register(publish(KEY["supplier-1"], "supplier-1", DECLARED))
fre("ctl-field-reader", "controls",
    "CONTROL: a verifier that reads the field would call this dataset fresh; the evidence does not",
    DECLARED, *evidence(log), WINDOW, {"state": "UNVERIFIED", "field_reader_sees": "2099-01-01T00:00:00Z"},
    extra={"field_reader_sees": declared_freshness_field(DECLARED)})

log = new_log(); log.register(R1); filler(log, 5, "f")
fre("lim-old-head", "limits",
    "LIMIT: handed an old but validly signed head, the verifier cannot tell it is not current", PART_A,
    *evidence(log, 4), WINDOW, {"state": "FRESH", "head_size": 4})


def main() -> None:
    doc = {"profile": "dataset.v1", "clauses": "Town proposal v0.3 sections 2, 4 and 5",
           "registry": {name: pub.hex() for name, pub in REGISTRY.items()},
           "log_public_key": LOG_PUBLIC.hex(),
           "test_key_seeds": {name: seed.hex() for name, seed in SEED.items()},
           "vectors": vectors}
    with open("vectors.json", "w") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print(len(vectors), "vectors")


if __name__ == "__main__":
    main()
