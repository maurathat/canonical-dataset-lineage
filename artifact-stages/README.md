# Artifact, part 2: signed publication, lineage traversal and freshness

This directory extends the canonicalization artifact in `../artifact/` to the three protocol stages the paper lists as proposed: signed publication (Town proposal v0.3 §2), lineage traversal (§4) and receipt-backed freshness (§5). It is a standalone prototype in a Lab model. It is **not** the Town plugin, and it has not been run inside Town.

`canon.py` is a byte-identical copy of `../artifact/canon.py`; `run.py` refuses to pass if its SHA-256 differs from the published one.

## Files

| File | Purpose |
|---|---|
| `statement.py` | Signed Statements as COSE_Sign1 (EdDSA, CWT `iss`/`sub`), `publish()` with the owner-substitution control, and `verify_publication()`, which reports signature validity, issuer authentication, content binding and owner binding separately. |
| `lineage.py` | `traverse()`: walks the canonical parent set and gives every edge one state: Verified, Failed, Unresolved, Malformed or Cyclic. |
| `tlog.py` | The Lab transparency log: an RFC 9162 §2.1 Merkle tree with inclusion proofs and a signed tree head. Registration is idempotent. |
| `freshness.py` | Freshness statements and `check_freshness()`, which keeps inclusion, order and completeness apart. |
| `vectors.json` | 51 vectors. Each gives exact input bytes (base64) and the evidence a verifier would be handed, its pinned outcome (`expect`), and the outcome it was written to show (`want`). |
| `build_vectors.py` | Regenerates `vectors.json`. The build fails if the implementation disagrees with any `want`. |
| `run.py` | Recomputes every outcome from the vector's input alone, prints the stage summary and a runtime receipt. Exits 1 on any mismatch. |
| `results.txt` | The recorded run. |

`SHA256SUMS` covers every file in this directory except itself.

## Run

```
pip install -r requirements.txt
python3 run.py
shasum -a 256 -c SHA256SUMS
```

## What was measured

| Stage | Vectors | Result |
|---|---|---|
| `signed_publication` | 16 | 3 honest publications pass all four checks; 10 forged or damaged statements do not pass, each failing the check it targets; 2 publication attempts are rejected with a typed reason (`OWNER_MISMATCH`, `CONTENT_LESS`) and 1 is accepted. |
| `lineage` | 15 | 7 honest walks pass, including a diamond, a legacy `parent` spelling and a parent stored in a different encoding; 8 faulted walks do not pass. All five edge states are exercised. |
| `freshness` | 17 | Every vector reaches the outcome it targets: FRESH 4, STALE 5, UNVERIFIED 8. |
| controls and limits | 3 | See below. These are expected to show a weakness, not to pass. |

The inclusion-proof code is also checked exhaustively for every leaf index at every tree size below 65 (2,080 cases): each proof verifies at its own index and at no other.

### Retained review vectors covered here

| Retained vector (proposal §9) | Vector(s) |
|---|---|
| owner substitution (#34) | `pub-owner-substitution`, `pub-forged-owner` |
| typed-only parents (#50) | `lin-honest`, `lin-deep` |
| legacy-only parent (#50) | `lin-legacy-spelling` |
| phantom parent (#50) | `lin-phantom-in-content`, `lin-phantom-top-level` |
| broken parent (#34) | `lin-broken`, `lin-deep-broken` |
| cyclic parent (#34) | `lin-cyclic`, `lin-self-cycle` |
| tampering (#59) | `lin-tampered`, `pub-tampered-payload` |
| clock (#72) | `fre-clock-order`, `fre-future-clock` |
| stale replay (#34) | `fre-stale-replay`, `ctl-replay-non-idempotent-log` |

Conflicting dual spelling and duplicate parent are publication rejections and are already pinned in `../artifact/vectors.json` (`rej-conflict`, `rej-dup-parent`).

## Decisions made where v0.3 is silent

These are choices of this prototype. Each should be settled in the proposal before the Town implementation.

1. **Idempotent registration.** §5 says replaying an older statement "does not change its position". That holds only if the log returns the original position when a byte-identical statement is registered again. On a log that appends duplicates, anyone holding an old freshness statement can restore freshness (`ctl-replay-non-idempotent-log`).
2. **A uniquifier on freshness statements.** Ed25519 signatures are deterministic, so an owner's second refresh of the same dataset is byte-identical to the first. With idempotent registration it would never get a new position. The freshness payload therefore carries an optional `nonce`.
3. **Traversal continues through a Failed edge, for diagnosis only.** Under honest content addressing a cycle cannot verify, so a cycle is always reached through at least one Failed edge. Stopping at the first Failed edge would make the Cyclic state unreachable.
4. **Owner binding is reported at verification, not only enforced at publication.** A statement validly signed by one agent over a payload naming another owner passes signature, issuer and content checks; only `owner_binding` catches it (`pub-forged-owner`).
5. **Freshness payload shape.** `{"type":"dataset-freshness","schema_version":"1","dataset":<typed reference>}` plus optional `nonce` and `issued_at`. `issued_at` is parsed and never used.

## What this does not establish

- **Not the Town plugin.** No `dataset.v1` plugin, scenario, validator or event log. The eight-stage validator result and the `dataset-fingerprint.v1` control inside Town remain to be produced.
- **Lab model, not a Transparency Service.** The signed head is this prototype's own format. Consistency proofs between heads are not implemented.
- **Current-state authenticity is not evaluated.** The verifier is handed a head and cannot tell a current head from an old, validly signed one (`lim-old-head`). A deployment must name where the current head comes from.
- **No elapsed-time freshness.** The window is measured in log positions. No registration time is authenticated.
- **Keys.** Ed25519 through an explicit registry. The statements follow COSE_Sign1 with CWT claims but have not been interoperability-tested against another SCITT implementation.
- **One implementation.** Pinned outcomes were generated by this code. Honest statements were additionally verified with a second Ed25519 library, and the Merkle root construction matches the published Certificate Transparency test roots, but no independent implementation has reproduced the vectors.

## Keys

All keys are derived from public labels and listed in `vectors.json`. They are test keys and protect nothing.
