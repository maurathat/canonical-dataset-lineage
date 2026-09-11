"""Build vectors.json: every input as exact bytes (base64), with its pinned expected outcome.

Expected identifiers are pinned from this implementation. They guard against regressions and
give independent implementations a fixed target; they are not independent evidence.
"""
from __future__ import annotations

import base64
import json
import unicodedata

from canon import Reject, dataset_id, reference

E_NFD = unicodedata.normalize("NFD", "\u00e9")
PARENT_A, PARENT_B = "a" * 64, "b" * 64


def ref(digest: str) -> str:
    return json.dumps(reference(digest), ensure_ascii=False, separators=(",", ":"))


BASE = ('{"owner":"supplier-1","schema_version":"1","parents":[],'
        '"content":{"unit":"kg","rows":[[1,2],[3,4]],"label":"Caf\u00e9"}}')
NAME_BASE = BASE.replace('"label"', '"lab\u00e9l"')
TWO_PARENTS = BASE.replace('"parents":[]', '"parents":[%s,%s]' % (ref(PARENT_A), ref(PARENT_B)))
ONE_PARENT = BASE.replace('"parents":[]', '"parents":[%s]' % ref(PARENT_A))
MINIMAL = '{"owner":"o","schema_version":"1","parents":[],"content":%s}'

# (id, group, text-or-bytes, note, relation)
VECTORS = [
    ("base", "reference", BASE, "reference dataset", {}),
    ("name-base", "reference", NAME_BASE, "reference with a non-ASCII member name", {}),
    ("two-parents", "reference", TWO_PARENTS, "reference with parents A, B", {}),
    ("one-parent", "reference", ONE_PARENT, "reference with parent A", {}),
    ("re-key-order", "reencoding", '{"content":{"label":"Caf\u00e9","rows":[[1,2],[3,4]],"unit":"kg"},'
     '"parents":[],"schema_version":"1","owner":"supplier-1"}', "member order", {"equivalent_to": "base"}),
    ("re-whitespace", "reencoding", BASE.replace(",", ", ").replace(":", ": "), "insignificant whitespace",
     {"equivalent_to": "base"}),
    ("re-float", "reencoding", BASE.replace("[[1,2],[3,4]]", "[[1.0,2.0],[3.0,4.0]]"), "1 -> 1.0",
     {"equivalent_to": "base"}),
    ("re-exponent", "reencoding", BASE.replace("[[1,2],[3,4]]", "[[1e0,2e0],[3e0,4e0]]"), "1 -> 1e0",
     {"equivalent_to": "base"}),
    ("re-nfd-value", "reencoding", BASE.replace("Caf\u00e9", "Caf" + E_NFD), "NFD string value",
     {"equivalent_to": "base"}),
    ("re-nfd-name", "reencoding", NAME_BASE.replace("lab\u00e9l", "lab" + E_NFD + "l"), "NFD member name",
     {"equivalent_to": "name-base"}),
    ("re-escape", "reencoding", BASE.replace("Caf\u00e9", "Caf\\u00e9"), "\\u escape",
     {"equivalent_to": "base"}),
    ("par-order", "parents", BASE.replace('"parents":[]', '"parents":[%s,%s]' % (ref(PARENT_B), ref(PARENT_A))),
     "parents in reverse order", {"equivalent_to": "two-parents"}),
    ("par-legacy", "parents", BASE.replace('"parents":[]', '"parent":"%s"' % PARENT_A), "legacy single parent",
     {"equivalent_to": "one-parent"}),
    ("par-dual", "parents", BASE.replace('"parents":[]', '"parents":[%s],"parent":"%s"' % (ref(PARENT_A), PARENT_A)),
     "identical dual spelling", {"equivalent_to": "one-parent"}),
    ("mut-number", "mutation", BASE.replace("[3,4]", "[3,5]"), "leaf number", {"differs_from": "base"}),
    ("mut-string", "mutation", BASE.replace('"kg"', '"g"'), "leaf string", {"differs_from": "base"}),
    ("mut-owner", "mutation", BASE.replace("supplier-1", "supplier-2"), "owner", {"differs_from": "base"}),
    ("mut-parent", "mutation", ONE_PARENT, "parent added", {"differs_from": "base"}),
    ("empty-object", "empty", MINIMAL % "{}", "content {}", {}),
    ("empty-array", "empty", MINIMAL % "[]", "content []", {}),
    ("empty-string", "empty", MINIMAL % '""', 'content ""', {}),
    ("empty-null", "empty", MINIMAL % "null", "content null", {}),
    ("rej-bom", "rejection", b"\xef\xbb\xbf" + (MINIMAL % "1").encode(), "byte-order mark", {}),
    ("rej-utf8", "rejection", (MINIMAL % '"X"').encode().replace(b"X", b"\xc3\x28"), "invalid UTF-8", {}),
    ("rej-syntax", "rejection", MINIMAL % "1" + "}", "malformed JSON", {}),
    ("rej-non-finite", "rejection", MINIMAL % "NaN", "non-finite number", {}),
    ("rej-not-object", "rejection", "[]", "top-level value is not an object", {}),
    ("rej-duplicate", "rejection", '{"owner":"o","owner":"p","schema_version":"1","parents":[],"content":1}',
     "duplicate member", {}),
    ("rej-nfc-collision", "rejection", MINIMAL % ('{"\u00e9":1,"%s":2}' % E_NFD), "NFC name collision", {}),
    ("rej-int-range", "rejection", MINIMAL % "9007199254740992", "integer 2^53", {}),
    ("rej-float-range", "rejection", MINIMAL % "9007199254740993.0", "float-spelled 2^53+1", {}),
    ("rej-fraction", "rejection", MINIMAL % "0.1", "non-integral", {}),
    ("rej-surrogate", "rejection", MINIMAL % '"\\ud800"', "lone surrogate", {}),
    ("rej-content-less", "rejection", '{"owner":"o","schema_version":"1","parents":[]}', "no content", {}),
    ("rej-no-owner", "rejection", '{"schema_version":"1","parents":[],"content":1}', "no owner", {}),
    ("rej-no-parents", "rejection", '{"owner":"o","schema_version":"1","content":1}', "no parent spelling", {}),
    ("rej-owner-type", "rejection", '{"owner":1,"schema_version":"1","parents":[],"content":1}', "owner not a string", {}),
    ("rej-schema", "rejection", '{"owner":"o","schema_version":"99","parents":[],"content":1}', "unsupported schema_version", {}),
    ("rej-unknown", "rejection", '{"owner":"o","schema_version":"1","parents":[],"content":1,"parent_hint":"x"}',
     "unknown top-level member", {}),
    ("rej-address", "rejection", '{"owner":"o","schema_version":"1","parents":[],"content":1,"address":"nothex"}',
     "malformed carried address", {}),
    ("rej-reference", "rejection", '{"owner":"o","schema_version":"1","content":1,"parents":[{"type":"dataset","digest":"%s"}]}'
     % PARENT_A, "reference missing digest_alg", {}),
    ("rej-conflict", "rejection", '{"owner":"o","schema_version":"1","content":1,"parents":[%s],"parent":"%s"}'
     % (ref(PARENT_A), PARENT_B), "conflicting parent spellings", {}),
    ("rej-dup-parent", "rejection", '{"owner":"o","schema_version":"1","content":1,"parents":[%s,%s]}'
     % (ref(PARENT_A), ref(PARENT_A)), "duplicate parent", {}),
    ("alias-0.1", "former-alias", MINIMAL % "0.10000000000000001", "binary64 alias of 0.1", {}),
    ("alias-1.1", "former-alias", MINIMAL % "1.1000000000000001", "binary64 alias of 1.1", {}),
]


def main() -> None:
    base_id = dataset_id(BASE.encode())
    out = []
    for vid, group, data, note, relation in VECTORS:
        raw = data if isinstance(data, bytes) else data.encode()
        try:
            expect = {"identifier": dataset_id(raw)}
        except Reject as r:
            expect = {"reject": r.reason}
        out.append({"id": vid, "group": group, "note": note,
                    "input_b64": base64.b64encode(raw).decode(), "expect": expect, **relation})
    for vid, address, matches in (("addr-correct", base_id, True), ("addr-wrong", "0" * 64, False)):
        raw = (BASE[:-1] + ',"address":"%s"}' % address).encode()
        out.append({"id": vid, "group": "exclusion", "note": "carried address " + ("correct" if matches else "wrong"),
                    "input_b64": base64.b64encode(raw).decode(), "expect": {"identifier": dataset_id(raw)},
                    "equivalent_to": "base", "carried_address_matches": matches})
    with open("vectors.json", "w") as f:
        json.dump({"profile": "dataset.v1", "pipeline": "Town proposal v0.3 section 1", "vectors": out}, f, indent=1)
        f.write("\n")


if __name__ == "__main__":
    main()
