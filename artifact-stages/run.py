"""Check every vector in vectors.json for the signed-publication, lineage and freshness stages.

    python3 run.py        # exits 1 on any mismatch

Each outcome is recomputed from the vector's input alone: statement bytes, resolver contents,
log head and receipts. The log is not rebuilt here; the verifier sees only the evidence.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.metadata as md
import json
import platform
import sys
import unicodedata

from canon import Reject
from freshness import check_freshness, declared_freshness_field
from lineage import traverse
from statement import Key, publication_passes, publish, verify_publication
from tlog import inclusion_path, merkle_root, verify_inclusion

CANON_SHA256 = "48d6ad1c92a292b1979ef05bc3010007ba0120e5da0d3be5f3f4f9b77902eb8d"
d64 = base64.b64decode


def recompute(v: dict, doc: dict) -> dict:
    registry = {name: bytes.fromhex(pub) for name, pub in doc["registry"].items()}
    i = v["input"]
    if v["stage"] == "signed_publication":
        if "publish" in i:
            agent, raw = i["publish"]["agent"], d64(i["publish"]["payload_b64"])
            try:
                statement = publish(Key(bytes.fromhex(doc["test_key_seeds"][agent])), agent, raw)
            except Reject as r:
                return {"published": False, "reject": r.reason}
            return {"published": True, "identifier": verify_publication(statement, registry)["identifier"]}
        result = verify_publication(d64(i["statement_b64"]), registry)
        result["pass"] = publication_passes(result)
        return result
    if v["stage"] == "lineage":
        return traverse(d64(i["root_b64"]), {d: d64(r) for d, r in i["store"].items()})
    entries = [{"statement": d64(e["statement_b64"]), "receipt": e["receipt"]} for e in i["entries"]]
    dataset = d64(i["dataset_b64"])
    result = check_freshness(dataset, registry, bytes.fromhex(doc["log_public_key"]), i["head"],
                             entries, i["window"])
    if "field_reader_sees" in v["expect"]:
        result["field_reader_sees"] = declared_freshness_field(dataset)
    return result


def merkle_self_test(limit: int = 65) -> tuple[int, int]:
    """Every (index, size) up to `limit`: the proof verifies, and fails at every other index."""
    ok = total = 0
    for size in range(1, limit):
        entries = [bytes([i]) * 3 for i in range(size)]
        root = merkle_root(entries).hex()
        for index in range(size):
            path = [p.hex() for p in inclusion_path(index, entries)]
            good = verify_inclusion(entries[index], index, size, path, root)
            wrong = any(verify_inclusion(entries[index], other, size, path, root)
                        for other in range(size) if other != index)
            total += 1
            ok += good and not wrong
    return ok, total


def main() -> int:
    doc = json.load(open("vectors.json"))
    vectors = doc["vectors"]
    failures = []
    canon_digest = hashlib.sha256(open("canon.py", "rb").read()).hexdigest()
    if canon_digest != CANON_SHA256:
        failures.append(f"canon.py digest is {canon_digest}; expected the published {CANON_SHA256}")

    got = {}
    for v in vectors:
        got[v["id"]] = recompute(v, doc)
        if got[v["id"]] != v["expect"]:
            failures.append(f"{v['id']}: expected {v['expect']}, got {got[v['id']]}")
        for key, value in v["want"].items():
            if got[v["id"]].get(key) != value:
                failures.append(f"{v['id']}: written to show {key}={value!r}, got {got[v['id']].get(key)!r}")

    stage = lambda s: [v for v in vectors if v["stage"] == s]  # noqa: E731
    pubs, lins, fres = stage("signed_publication"), stage("lineage"), stage("freshness")
    verified = [v for v in pubs if "statement_b64" in v["input"]]
    attempts = [v for v in pubs if "publish" in v["input"]]
    edge_states: dict[str, int] = {}
    for v in lins:
        for state, n in got[v["id"]]["states"].items():
            edge_states[state] = edge_states.get(state, 0) + n
    fre_states: dict[str, int] = {}
    for v in fres:
        fre_states[got[v["id"]]["state"]] = fre_states.get(got[v["id"]]["state"], 0) + 1
    m_ok, m_total = merkle_self_test()
    if m_ok != m_total:
        failures.append(f"merkle self-test {m_ok}/{m_total}")

    count = lambda vs, pred: sum(1 for v in vs if pred(got[v["id"]]))  # noqa: E731
    print("STAGES (standalone prototype, Lab model; not the Town plugin)")
    print("  signed_publication")
    print(f"    honest publications passing all four checks   {count(verified, lambda r: r.get('pass'))}/{sum(1 for v in verified if v['want'].get('pass'))}")
    print(f"    forged or damaged statements not passing      {count(verified, lambda r: not r.get('pass'))}/{sum(1 for v in verified if not v['want'].get('pass'))}")
    print(f"    publication attempts rejected with a reason   {count(attempts, lambda r: not r['published'])}/{sum(1 for v in attempts if not v['want']['published'])}")
    print("  lineage")
    print(f"    honest walks passing                          {count(lins, lambda r: r['pass'])}/{sum(1 for v in lins if v['want']['pass'])}")
    print(f"    faulted walks not passing                     {count(lins, lambda r: not r['pass'])}/{sum(1 for v in lins if not v['want']['pass'])}")
    print("    edge states reported                          " + ", ".join(f"{s} {n}" for s, n in sorted(edge_states.items())))
    print("  freshness")
    print("    outcomes                                      " + ", ".join(f"{s} {n}" for s, n in sorted(fre_states.items())))
    print(f"    vectors matching the outcome they target      {sum(1 for v in fres if all(got[v['id']].get(k) == x for k, x in v['want'].items()))}/{len(fres)}")
    print(f"    inclusion-proof self-test (all index/size<65) {m_ok}/{m_total}")
    print("  controls and limits (expected to show the weakness, not to pass)")
    for v in stage("controls") + stage("limits"):
        print(f"    {v['id']:<32} {got[v['id']]['state']}")
    print(f"VECTORS {len(vectors)} checked, {len(failures)} failures")
    for f in failures:
        print("  FAIL", f)

    print("RECEIPT")
    print(f"  {platform.python_implementation()} {sys.version.split()[0]}; Unicode {unicodedata.unidata_version}")
    for pkg in ("rfc8785", "cbor2", "cryptography"):
        print(f"  {pkg} {md.version(pkg)}")
    for name in ("canon.py", "statement.py", "lineage.py", "tlog.py", "freshness.py", "vectors.json", "run.py"):
        print(f"  sha256 {hashlib.sha256(open(name, 'rb').read()).hexdigest()}  {name}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
