"""Check every vector in vectors.json against canon.py, compare re-encodings with Town's
records.fingerprint (the control), and print Table II plus a runtime receipt.

    TOWN_SRC=<nandatown>/src python3 run.py        # exits 1 on any mismatch
"""
from __future__ import annotations

import base64
import hashlib
import importlib.metadata as md
import json
import os
import platform
import subprocess
import sys
import unicodedata

from canon import Reject, carried_address_matches, dataset_id

TOWN_COMMIT = "df0b5f1fd0c2ec2f9535c786fcf83694096e4e9f"
TOWN_RECORDS_SHA256 = "de97b71b1b82b49a10965ff413230d5ca879461d4846e9df586242419c01c8cb"


def outcome(raw: bytes) -> dict:
    try:
        return {"identifier": dataset_id(raw)}
    except Reject as r:
        return {"reject": r.reason}


def load_control():
    src = os.environ.get("TOWN_SRC")
    if not src:
        return None, None, None
    sys.path.insert(0, src)
    import nandatown.records as records
    try:
        head = subprocess.run(["git", "-C", src, "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except Exception as exc:
        raise RuntimeError(f"Town control is not in a Git checkout: {src}") from exc
    digest = hashlib.sha256(open(records.__file__, "rb").read()).hexdigest()
    if head != TOWN_COMMIT:
        raise RuntimeError(f"Town control commit is {head}; expected {TOWN_COMMIT}")
    if digest != TOWN_RECORDS_SHA256:
        raise RuntimeError(f"Town records.py digest is {digest}; expected {TOWN_RECORDS_SHA256}")
    return records.fingerprint, head, digest


def main() -> int:
    vectors = json.load(open("vectors.json"))["vectors"]
    by_id = {v["id"]: v for v in vectors}
    raw = {v["id"]: base64.b64decode(v["input_b64"]) for v in vectors}
    try:
        fingerprint, head, control_digest = load_control()
    except RuntimeError as exc:
        print(f"CONTROL ERROR: {exc}", file=sys.stderr)
        return 1

    failures = []
    for v in vectors:
        got = outcome(raw[v["id"]])
        if got != v["expect"]:
            failures.append(f"{v['id']}: expected {v['expect']}, got {got}")
        if "equivalent_to" in v and got != outcome(raw[v["equivalent_to"]]):
            failures.append(f"{v['id']}: not equivalent to {v['equivalent_to']}")
        if "differs_from" in v and got == outcome(raw[v["differs_from"]]):
            failures.append(f"{v['id']}: does not differ from {v['differs_from']}")
        if "carried_address_matches" in v and carried_address_matches(raw[v["id"]]) != v["carried_address_matches"]:
            failures.append(f"{v['id']}: carried-address check wrong")

    group = lambda g: [v for v in vectors if v["group"] == g]  # noqa: E731
    reenc = group("reencoding")
    one_id = sum(outcome(raw[v["id"]]) == outcome(raw[v["equivalent_to"]]) for v in reenc)
    control = "n/a"
    if fingerprint:
        same = sum(fingerprint(json.loads(raw[v["id"]])) == fingerprint(json.loads(raw[v["equivalent_to"]]))
                   for v in reenc)
        control = f"{same}/{len(reenc)}"
    parents = group("parents")
    empties = {outcome(raw[v["id"]])["identifier"] for v in group("empty")}
    rejections = group("rejection")
    fired = sum(outcome(raw[v["id"]]) == v["expect"] for v in rejections)
    reasons = {v["expect"]["reject"] for v in rejections}
    aliases = group("former-alias")

    print("TABLE II")
    print(f"  re-encodings resolving to one identity   {one_id}/{len(reenc)}   control {control}")
    print(f"  parent spellings resolving to one identity {sum(outcome(raw[v['id']]) == outcome(raw[v['equivalent_to']]) for v in parents)}/{len(parents)}")
    print(f"  mutations moving the identity             {sum(outcome(raw[v['id']]) != outcome(raw[v['differs_from']]) for v in group('mutation'))}/{len(group('mutation'))}")
    print(f"  empty values with distinct identities     {len(empties)}/{len(group('empty'))}")
    print(f"  rejection vectors fired as pinned         {fired}/{len(rejections)} ({len(reasons)} typed reasons)")
    print(f"  former binary64 aliases refused           {sum('reject' in outcome(raw[v['id']]) for v in aliases)}/{len(aliases)}")
    print(f"  carried-address checks                    {sum(1 for v in group('exclusion') if carried_address_matches(raw[v['id']]) == v['carried_address_matches'])}/{len(group('exclusion'))}")
    print(f"VECTORS {len(vectors)} checked, {len(failures)} failures")
    for f in failures:
        print("  FAIL", f)

    print("RECEIPT")
    print(f"  {platform.python_implementation()} {sys.version.split()[0]}; Unicode {unicodedata.unidata_version}")
    for pkg in ("rfc8785", "pydantic", "pydantic_core", "annotated-types",
                "typing_extensions", "typing-inspection"):
        try:
            print(f"  {pkg} {md.version(pkg)}")
        except md.PackageNotFoundError:
            print(f"  {pkg} not installed")
    for name in ("canon.py", "vectors.json", "run.py"):
        print(f"  sha256 {hashlib.sha256(open(name, 'rb').read()).hexdigest()}  {name}")
    if fingerprint:
        print(f"  control: nandatown {head}; records.py sha256 {control_digest}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
