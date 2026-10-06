"""Regenerate Table I: one dataset, four profile-equivalent encodings, three digest recipes.

    TOWN_SRC=<nandatown>/src python3 table1.py    # fingerprint column measured on Town
    python3 table1.py                             # fingerprint column computed locally

The three columns are digest *recipes*, not the dataset profile of canon.py: the
table's subject is a bare dataset value, not a `dataset` payload, so the profile's
closed schema does not apply. The fingerprint recipe is Town's `records.fingerprint`
when TOWN_SRC is set; otherwise an equivalent local serialization (sorted member
names, compact separators, UTF-8 emitted directly rather than \\u-escaped) is used
and labelled as such in the receipt.
"""
from __future__ import annotations

import hashlib
import importlib.metadata as md
import json
import os
import subprocess
import sys
import unicodedata

import rfc8785

TOWN_COMMIT = "df0b5f1fd0c2ec2f9535c786fcf83694096e4e9f"

# Exact input bytes for each encoding. Written out rather than built from objects so
# the number spellings and the Unicode normalization form are visible in the source.
ENCODINGS: list[tuple[str, bytes]] = [
    ("original",
     b'{"unit":"kg","rows":[[1,2],[3,4]],"label":"Caf\xc3\xa9"}'),
    ("members reordered",
     b'{"label":"Caf\xc3\xa9","rows":[[1,2],[3,4]],"unit":"kg"}'),
    ("integral-valued floats",
     b'{"unit":"kg","rows":[[1.0,2.0],[3.0,4.0]],"label":"Caf\xc3\xa9"}'),
    ('"Café" in NFD',
     b'{"unit":"kg","rows":[[1,2],[3,4]],"label":"Cafe\xcc\x81"}'),
]


def bare_hex(value: str) -> str:
    """Town's records.fingerprint() returns 'sha256:<hex>'; the table shows bare digests.

    Stripping the algorithm label is a presentation step only: the digest itself is
    unchanged. The form is asserted so a change upstream fails loudly instead of
    silently slicing a prefix into the table.
    """
    digest = value.rsplit(":", 1)[-1]
    if len(digest) != 64 or digest.strip("0123456789abcdef"):
        raise SystemExit(f"unexpected fingerprint form: {value!r}")
    return digest


def load_town_fingerprint():
    src = os.environ.get("TOWN_SRC")
    if not src:
        return None, None, None
    sys.path.insert(0, src)
    import nandatown.records as records
    try:
        head = subprocess.run(["git", "-C", src, "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        head = "unknown"
    digest = hashlib.sha256(open(records.__file__, "rb").read()).hexdigest()
    return records.fingerprint, head, digest


def local_fingerprint(value) -> str:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def jcs(value) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def to_nfc(value):
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [to_nfc(item) for item in value]
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", k): to_nfc(v) for k, v in value.items()}
    return value


def main() -> int:
    town_fingerprint, head, control_digest = load_town_fingerprint()
    if town_fingerprint is not None:
        def fingerprint(value):
            return bare_hex(town_fingerprint(value))
    else:
        fingerprint = local_fingerprint

    print("TABLE I  (digest prefixes, 8 hex characters)")
    print(f"  {'encoding':30s} {'fingerprint':12s} {'JCS':12s} NFC->JCS")
    baseline = None
    for name, raw in ENCODINGS:
        value = json.loads(raw.decode("utf-8"))
        row = (fingerprint(value)[:8], jcs(value)[:8], jcs(to_nfc(value))[:8])
        if baseline is None:
            baseline = row
        marks = tuple("*" if cell != base else " " for cell, base in zip(row, baseline))
        print(f"  {name:30s} {row[0]}{marks[0]}    {row[1]}{marks[1]}    {row[2]}{marks[2]}")
    print("  * marks a fork: the identifier differs from the original encoding's.")

    print("RECEIPT")
    print(f"  CPython {sys.version.split()[0]}; Unicode {unicodedata.unidata_version}")
    for pkg in ("rfc8785",):
        try:
            print(f"  {pkg} {md.version(pkg)}")
        except md.PackageNotFoundError:
            print(f"  {pkg} not installed")
    print(f"  sha256 {hashlib.sha256(open(__file__, 'rb').read()).hexdigest()}  {os.path.basename(__file__)}")
    if town_fingerprint:
        note = "" if head == TOWN_COMMIT else f"  (expected {TOWN_COMMIT})"
        print(f"  fingerprint: nandatown {head}{note}; records.py sha256 {control_digest}")
        print("  fingerprint form: records.fingerprint() returns 'sha256:<hex>'; the "
              "algorithm label is stripped for display, the digest is unchanged")
    else:
        print("  fingerprint: computed locally (TOWN_SRC unset); sorted names, compact "
              "separators, UTF-8 emitted directly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
