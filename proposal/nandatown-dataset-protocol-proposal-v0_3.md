# A dataset protocol for Town — proposal draft v0.3

*For discussion on projnanda/nandatown. Written against `main` at `df0b5f1` (Sep 7 2026) and `draft-mih-sokolov-scitt-payload-binding-03` (Sep 5 2026). Author: Maura Clark (@maurathat). Status: draft for review; nothing here is implemented against current `main`.*

**Disclosure first.** This proposal uses CPB's draft-local `jcs` algorithm with a dataset-profile transformation defined in §1. I also author the related `uor-jcs-nfc` digest context and hold its Apache-2.0 copyright. Its specification, reference implementation, and a provisional RC5 corpus are public, but its final `uor-vectors-v2` corpus is not yet designated. This proposal does not select `uor-jcs-nfc`: that context admits integer number tokens only, while Town's retained re-encoding requirement includes `1` → `1.0`. I also contribute to the UOR Foundation. The proposed plugin would be Town code with no external package dependency.

## Summary

Agents re-export datasets from one tool into another, derive new datasets from several inputs, refresh datasets that are still in use, and hand datasets across owners. Town's `data_facts` layer records one attributed, signed fact per record. That is the right shape for evidence, and this proposal leaves it alone. What Town lacks is a contract for the dataset itself: an identity that survives re-encoding, an owner bound by signature, parents that can be traversed and checked, and freshness that is proven rather than inferred.

Five legacy PRs were recently closed as seeds of future profiles rather than as repairs to current code. Three of them (#72, #50, #34) describe this missing dataset contract, and two more (#59, #61) would build on it. This draft assembles those requirements into one additive plugin, `dataset.v1`. Rather than inventing new machinery for identity, signing and ordering, it reuses the IETF SCITT stack: the CPB construction for canonical identity and typed references, RFC 9943 Signed Statements for ownership, and a Transparency Service's VDS-specific proofs for inclusion and ordering. What remains specific to Town is dataset semantics: parents, absent and empty content, freshness, and the evaluator stages.

### Workshop relevance

The implementation and adversarial evaluation proposed here fit the [IEEE TPS 2026 NANDA workshop](https://projectnanda.org/workshops/ieeetps26/) under trust/accountability and evaluation/red-teaming. This GitHub discussion draft is not the submission manuscript. A workshop submission would be a separate IEEE-format short paper, limited to four pages including references, and would report only results actually produced by the rebuilt `dataset.v1` implementation and its negative control. If those results are not ready, the submission should instead be framed as a position paper and label the evaluation as proposed rather than measured. The deadline posted on September 11 is September 17, 2026 at 23:59 AoE.

## Why a separate identity, and not `records.fingerprint`

`records.fingerprint` hashes `canonical_json`: sorted keys, compact separators, no ASCII escaping. As Town's stable fingerprint of its parsed record model, which is also what `hmac.v1` signs, that is correct. For dataset identity it is not enough. Here is one logical dataset in four encodings, measured on `df0b5f1`:

| Encoding of `{unit:"kg", rows:[[1,2],[3,4]], label:"Café"}` | `records.fingerprint` | CPB `jcs` | `dataset.v1` (NFC → `jcs`) |
|---|---|---|---|
| original | `965293f8…` | `965293f8…` | `965293f8…` |
| keys reordered | `965293f8…` | `965293f8…` | `965293f8…` |
| integers as floats (`1` → `1.0`) | **`6332808b…`** | `965293f8…` | `965293f8…` |
| `"Café"` in NFD | **`30d12650…`** | **`30d12650…`** | `965293f8…` |

On this input, Town's bytes already equal RFC 8785 output, so adopting JCS changes nothing that works today. JCS fixes the number fork. Only the profile's Unicode-normalization step fixes the NFD fork.

`canonical_json` and `fingerprint` stay untouched, so no stored evidence fingerprint changes.

## Requirements, from the closing comments

| Source | Requirement (paraphrased) |
|---|---|
| #72 | Re-encodings resolve to one identity; a leaf mutation changes it; empty inputs get explicit, non-colliding handling; freshness and merge never depend on a writer's private clock. |
| #50 | Two supported parent spellings canonicalize to one identity; conflicting spellings fail; a parent not bound into the canonical bytes never affects provenance. A dataset type needs publication, lifecycle, verification and evaluator semantics, not just a schema. |
| #34 | One canonical byte encoding; content-derived identity; signed owner binding; independently traversable parents; freshness verified cryptographically rather than inferred from fields; a broken-link control. |
| #59 | (Interview evidence, composes on top.) Quotes are parent-bound to a content-addressed transcript; raw PII is redacted before hashing. |
| #61 | (Payments, composes on top.) Units settle only against a precommitted criterion; a deliberately broken control must fail. |

## Scope

In scope:
- A new plugin, `@register("data_facts", "dataset.v1")`, defining a `dataset` payload class, its publication, its verification, and its evaluator stages.
- A negative-control plugin, a scenario, and validators.
- An asymmetric signing plugin (Q4).
- A Lab-local transparency log for ordering.

Out of scope:
- Changes to `evidence.v1`, `canonical_json` or `fingerprint`.
- Access control, payments, and merge semantics.
- Revocation.
- A deployed Transparency Service or deployed NANDA Index; the Lab models the log locally.

## 1. Canonicalization

The `dataset` payload class selects exactly one CPB canonicalization algorithm: `jcs`. Before derived-identifier computation it applies the profile-owned transformation below. CPB permits such a transformation only when the profile fixes its order relative to field exclusion and the selected algorithm; this section does so.

The complete order is normative:

1. **Admit and validate the complete JSON payload.** Decode the input bytes as strict UTF-8 with no byte-order mark (`INVALID_UTF8`, `BOM_PRESENT`); reject malformed JSON (`MALFORMED_JSON`). Reject duplicate member names after JSON escape decoding, non-scalar Unicode content, `NaN`, and infinities. Judge every number token on its decimal spelling, before any binary conversion: it must be mathematically integral (else `NUMBER_NOT_INTEGRAL`) and within ±(2^53 − 1) (else `NUMBER_OUT_OF_RANGE`). A value rejected here, whether non-integral or out of range, must be carried as a string.
2. **Apply the dataset transformation to the complete payload, before exclusion.** Fold every string value and object member name to Unicode NFC, recursively. Reject two member names that become identical after folding. Enforce the closed payload shape of §2. Normalize the accepted `parent`/`parents` spellings and declared set semantics as specified in §4. This validation includes fields that will later be excluded, so exclusion cannot hide malformed input.
3. **Apply the exclusion set.** Remove the top-level `address` member, if present. No nested member is removed. `content`, `owner`, `parents`, and `schema_version` remain in the preimage.
4. **Apply CPB `jcs`.** Serialize with RFC 8785 JCS, compute SHA-256, and encode the digest as exactly 64 lowercase hexadecimal characters.

The numeric domain is therefore the integers within ±(2^53 − 1), in any JSON spelling: `1`, `1.0` and `1e0` are one value and share an identity, as #72 requires. Every non-integral quantity, including money and physical measurements, is carried as a string. This is deliberate. Admitting general binary64 values, as plain JCS does, inherits input rounding: the prototype confirmed that `0.1` and `0.10000000000000001` would share an identity, as would the float-spelled `9007199254740992.0` and `9007199254740993.0`. Under this domain all of them are refused, and no two distinct numbers share an identity.

This construction is not `uor-jcs-nfc`. That context refuses every floating-point token, including `1.0`, and renders digests as `sha256:<hex>`. Reusing that name here would give one token two admission domains and two representations. If Town later adopts an integer-only payload class, that class may cite `uor-jcs-nfc` as a distinct digest context; `dataset.v1` does not. Moving `dataset.v1` itself onto `uor-jcs-nfc` would mean rejecting every floating-point token and rewriting the retained `1` → `1.0` invariance vector as a refusal test.

## 2. Identity and publication

**The payload.** A dataset payload has four members: `content`, `owner`, `parents` (in canonical form, §4) and `schema_version`. The top-level object is closed. It may also carry the legacy `parent` spelling (§4) and the excluded `address`; any other top-level member is rejected (`UNKNOWN_MEMBER`), so nothing unlisted can silently enter the identity. `owner` is a non-empty string (`INVALID_OWNER`). `schema_version` is `"1"` for `dataset.v1` (`UNSUPPORTED_SCHEMA_VERSION`). A carried `address` must be 64 lowercase hexadecimal characters (`MALFORMED_ADDRESS`). A missing member is `MISSING_MEMBER`, except a missing `content`, which is `CONTENT_LESS` (§3). Extensions belong inside `content` or require a new `schema_version`. Its derived identifier is the canonical digest of that payload with the exclusion set removed. The exclusion set is `{address}`, meaning the carried identifier field, if present, because a field can't be inside the preimage it helps compute. A verifier always recomputes the identifier; a carried value is advisory, and a mismatch is a defect.

**Representation.** Identifiers are bare 64-character lowercase hex, which matches CPB's default output and typed references. A prefixed display form is open question Q7. CPB forbids silent coercion between representations.

**Publication.** Publishing produces an RFC 9943 Signed Statement in Full-Content Mode:
- The payload is the dataset.
- The protected `content_type` header is `application/json`. A future profile-specific media type would be a versioned protocol change.
- The CWT `iss` claim is the owner, and the `sub` claim is the derived identifier.
- If the declared `owner` differs from the issuing agent, publication is rejected with `OWNER_MISMATCH`. This is the owner-substitution control.

**Verification.** A verifier reports signature validity, issuer authentication, and content binding as separate results, following CPB's state model. It never collapses them into one pass. A valid signature proves that a key committed to the statement, not that the content is true; Town's docs and CPB both say this.

**Dependency.** Town's `hmac.v1` auth plugin cannot produce statements that a third party can verify. `dataset.v1` needs an asymmetric signing plugin to produce COSE signatures. That plugin is part of this proposal's implementation PR (Q4).

## 3. Absent and empty content

**Absent content** means the `content` member is missing. Publication rejects it with `CONTENT_LESS`.

A legacy identifier produced only by Town's `records.fingerprint` belongs to a *different artifact type*, `dataset-fingerprint`, whose digest context is the current `canonical_json` byte construction followed by SHA-256, represented as Town's prefixed text `sha256:<64 lowercase hex>` (the exact output of `records.fingerprint` at `df0b5f1`). It is never a `dataset` fallback. CPB requires that two digests be compared only under an established shared digest context, so a fingerprint-addressed record cannot be mistaken for a structurally canonical dataset, even after its prefix is stripped. This replaces the unmarked fallback in legacy `sic_facts`.

**Empty content** means values like `{}`, `[]`, `""` or `null`. These are content, not absence. CPB `jcs` applies no absent-field normalization: empty members count as present, and each empty value gets its own identifier (verified: all four digests differ). The related `uor-jcs-nfc` context also mandates retaining all four. The withdrawn CPB algorithm `jcs-n` removed some empty-valued object members before hashing; `dataset.v1` never applies that behaviour. Empty-value handling is therefore closed, not an open canon question.

## 4. Parents

**Encoding.** Parents are a set of CPB typed digest references. Each reference is a closed JSON object containing exactly `type: "dataset"`, `digest_alg: "SHA-256"`, and `digest: <64 lowercase hex characters>`; `purpose` is absent because the type has one accepted context. An unknown or duplicate member makes the reference Malformed. `dataset.v1` selects profile-owned payload carriage for these references; the same Signed Statement must not also carry a `cpb-refs` protected header. The references travel in the payload, so the child's identifier commits to its parents. Parents are deliberately *not* in the exclusion set. The exclusion set is for self-reference and for records that chain on *later*.

**Digest-context declaration.** This specification declares the `dataset` artifact type and its single digest context: the ordered §1 transformation, exclusion and `jcs` pipeline; SHA-256; and bare lowercase-hex comparison representation. With only one context, no CPB `purpose` selector is needed. A consuming profile identifies this declaration by a stable, revision-pinned reference. The `dataset-fingerprint` context declared in §3 is separate and never interchangeable with `dataset`.

**Accepted spellings.** `dataset.v1` accepts two spellings, normalized by the §1 transformation before exclusion and canonicalization:
- A typed `parents` array, used as given.
- A legacy single `parent` digest, which becomes a one-element set.
- If both are present and denote the same set, they collapse to it.
- If both are present and conflict, publication fails with `PARENT_SPELLING_CONFLICT`.

**Set semantics.** Parents are sorted by digest, so order never affects identity. A repeated parent is rejected with `DUPLICATE_PARENT` (open question Q2).

**No phantom edges.** Lineage is computed only from the canonical `parents` set. A parent reference inside `content` is ordinary content and never creates an edge; an unlisted top-level member, such as a `parent_hint`, is rejected outright.

**Traversal** maps each edge onto CPB's reference states:

| State | Meaning |
|---|---|
| Verified | The parent was obtained and its recomputed identifier matches. |
| Failed | The recomputed identifier differs from the reference (tampering). |
| Unresolved | The parent cannot be obtained (broken link). |
| Malformed | The reference is structurally invalid. |

On top of those, the profile adds **Cyclic**. Under honest content addressing a cycle cannot occur, so a revisited node means a forged reference, and traversal must detect it and terminate. CPB leaves the handling of every non-Verified state to the consuming profile. Here, none of them ever counts as a pass.

## 5. Freshness and ordering

CPB states explicitly that content binding does not establish freshness. So this profile defines freshness itself, on top of SCITT ordering:

- **Freshness statements.** A freshness statement is a Signed Statement from the owner, citing the dataset's identifier as a typed reference, registered with a Transparency Service.
- **Inclusion and order are separate evidence.** A verified Receipt establishes registration in the selected VDS. Relative order comes only from a VDS proof or Receipt Profile that exposes a verifiable Statement Sequence position. A bare inclusion proof with no comparable position is insufficient to establish supersession. For example, `RFC9162_SHA256` inclusion proofs expose a leaf index and tree size, and consistency proofs to a signed current tree head establish the current state. Completeness (below) still needs a named query, index or monitor.
- **No writer clock.** Producer timestamps never determine order. In the Lab, the VDS is a local append-only sequence whose position is the engine's logical tick, matching Town's determinism rules.
- **Discovery completeness is separate evidence.** A receipt for one statement does not prove that no later matching statement exists. A freshness verifier needs an authenticated current VDS state plus a complete, auditable enumeration of freshness statements for the `(owner, dataset identifier)` pair. The Lab can enumerate its local log; a deployment must name the query, index, or monitor that supplies this property.
- **Proven, not inferred.** The current freshness statement is the owner-authenticated statement at the greatest verified sequence position in that complete result set. The Lab's freshness window is expressed in positions relative to its authenticated current head. A deployment that claims elapsed-time freshness must additionally use a Transparency-Service-authenticated registration time bound by its Receipt Profile; an issuer's timestamp is insufficient. A `freshness` field without the required evidence is unverified, never fresh.
- **Monotonic supersession.** A statement at a later verified position supersedes one at an earlier position. Replaying an older valid statement does not change its position and cannot restore freshness when verification uses the authenticated current state and complete result set.
- **No clobbering.** Only statements issued by the owner count as freshness. A non-owner republishing the same content reaches the same identifier, but cannot refresh it.

## 6. Lifecycle

Datasets are immutable. A new version is a new dataset that lists its predecessor in `parents`. The lifecycle has three stages:
1. **Published**, or rejected with a typed reason.
2. **Fresh or stale**, per §5.
3. **Superseded**, informationally, once a child names it as a parent.

Revocation and merge are out of scope. Any later merge rule must depend only on content, lineage and log order.

## 7. Evaluator semantics

The plugin emits events so that every stage can be recomputed from `events.jsonl` alone:
- `dataset_published`: identifier, owner, parents, algorithm (`jcs`) and `dataset.v1` transformation revision
- `dataset_rejected`: typed reason
- `freshness_registered` and `freshness_checked`: including sequence position, the authenticated current head, and the completeness evidence used
- `lineage_checked`: root, the edges walked, and each edge's state
- `reencode_checked`: both identifiers and whether they are equal

A validator, `@validator("dataset_provenance")`, reports eight stages:

| Stage | Passes when |
|---|---|
| `input_validation` | Every §1–§2 rejection fires with its typed reason: encoding and syntax (`INVALID_UTF8`, `BOM_PRESENT`, `MALFORMED_JSON`, `NON_FINITE`), duplicate member name, NFC name collision, `NUMBER_NOT_INTEGRAL`, `NUMBER_OUT_OF_RANGE`, non-scalar Unicode, and the payload-shape and parent reasons (`NOT_AN_OBJECT`, `CONTENT_LESS`, `UNKNOWN_MEMBER`, `MISSING_MEMBER`, `INVALID_OWNER`, `UNSUPPORTED_SCHEMA_VERSION`, `MALFORMED_ADDRESS`, `MALFORMED_REFERENCE`, `PARENT_SPELLING_CONFLICT`, `DUPLICATE_PARENT`). |
| `canonical_identity` | Every re-encoding (key order, int→float, NFD, whitespace) resolves to its original's identifier. |
| `mutation_sensitivity` | Every single-leaf mutation moves the identifier. |
| `empty_input` | Absent content is rejected; the four empty values get four distinct identifiers. |
| `signed_publication` | Every publication is issuer-authenticated as its owner; owner substitution is rejected. |
| `lineage` | Honest chains verify; broken, tampered, cyclic and phantom cases are reported in their non-Verified states. |
| `freshness` | Ordering follows verified VDS positions under an authenticated current state and complete query; stale replay and non-owner refresh fail; elapsed-time claims require Receipt-Profile-bound service time. |
| `controls` | The negative control fails the stages it exists to fail. |

**Negative control.** A `dataset-fingerprint.v1` plugin identifies datasets with `records.fingerprint`. It exists to show what the protocol is for, the way `plain.v1` does in the auth layer. Its expected result is `canonical_identity: failed` on the int→float and NFD vectors.

## 8. Pilot scenario

The pilot is `dataset_provenance.yaml`, reusing the `supply_chain` roles plus a new `auditor` role:
- Suppliers publish part-specification datasets.
- The manufacturer publishes an assembly dataset whose parents are those parts.
- The auditor re-encodes, mutates, traverses, and checks freshness against the Lab log.

The injected faults cover every retained vector in §9. The scenario runs once with `dataset.v1` and once with the control. It is a Town-authored integration test, not evidence of external adoption.

## 9. Traceability

| Retained vector | Source | Clause | Stage |
|---|---|---|---|
| permutation (re-encoding) | #72 | §1, §2 | `canonical_identity` |
| mutation | #72 | §2 | `mutation_sensitivity` |
| empty input | #72 | §3 | `empty_input` |
| clock | #72 | §5 | `freshness` |
| typed-only parents | #50 | §4 | `lineage` |
| legacy-only parent | #50 | §4 | `lineage` |
| identical dual spelling | #50 | §4 | `canonical_identity` |
| conflicting dual spelling | #50 | §4 | `lineage` (publication rejected) |
| parent order | #50 | §4 | `canonical_identity` |
| duplicate parent | #50 | §4 | `lineage` (publication rejected) |
| phantom parent | #50 | §4 | `lineage` |
| canonicalization | #34 | §1 | `canonical_identity` |
| owner substitution | #34 | §2 | `signed_publication` |
| stale replay | #34 | §5 | `freshness` |
| broken parent | #34 | §4 | `lineage` (Unresolved) |
| cyclic parent | #34 | §4 | `lineage` (Cyclic) |
| tampering | #59 | §2, §4 | `mutation_sensitivity`, `lineage` (Failed) |
| PII, unauthorized viewer, fabricated quote | #59 | — | Interview-evidence profile; quote binding is a typed reference to a transcript dataset |
| correlation, cap, zero flow, no double bill, evaluator commitment | #61 | — | Payment profile; the evaluator criterion can be a typed reference to a dataset |

## 10. Open questions

- **Q1. Access tier.** Legacy `sic_facts` bound `access_tier` into identity. This draft leaves it out, on the reading that access is policy (#59), not identity.
- **Q2. Duplicate parents.** Reject (this draft) or deduplicate? The #50 duplicate vector should decide this.
- **Q3. Redaction ordering.** Town's `redact.v1` redacts fields at export, but #59 asks for redaction before hashing. Under CPB, salting and selective disclosure change the digest context and must be declared by the profile. The interview-evidence profile should declare its redaction as a transformation, so that in-run and exported identifiers agree.
- **Q4. Asymmetric signing in Town.** COSE statements need an asymmetric auth plugin. It ships with the implementation PR, or as a separate prerequisite PR.
- **Q5. Receipt Profile, VDS and discovery.** Which real Transparency Service supplies the authenticated current state, verifiable sequence positions, and complete query or monitor—and, if elapsed-time freshness is claimed, authenticated registration time—for the external pilot? The Lab model does not answer deployment interoperability.
- **Q6. External pilot.** Town's convergence doc asks for pilots and measured defects. The measured defect is the table above. No external pilot has committed yet.
- **Q7. Display form.** Should there be a prefixed display form in addition to the normative bare lowercase-hex comparison value, and if so, which prefix and explicit conversion operation?

## 11. Proposed path

1. **Agree the contract here.** Settle §1–§7 and Q1–Q2 in this discussion.
2. **Canonicalization vectors.** Pin public positive and negative vectors for the exact §1 pipeline, including transformation-before-exclusion, NFC name collisions, the integral numeric domain (including the refused binary64 aliases), empty values, and representation. These are `dataset.v1` profile vectors, not a new CPB registry entry.
3. **Implementation PR against current `main`.** This covers `dataset.v1`, `dataset-fingerprint.v1`, the asymmetric signing plugin, the Lab log, the scenario, the validator, and tests. It meets CONTRIBUTING's bar for importing legacy work: an explicit current requirement plus tests against the rebuilt implementation. No legacy code is imported.
4. **Pilot.** Pair with one external consumer and exercise a named Transparency Service, Receipt Profile, and VDS that satisfy Q5.

## Prior work

This draft consolidates requirements from the closing comments on #72 (`sic_facts`, @maurathat), #50 and #35 (@Ngoga-Musagi), #34 (@24f3003188), #59 (@puja-ankitha-ivaturi-ogha) and #61 (@chainaim-nisha), and reuses their retained vectors. The closed, unmerged #72 contributor implementation is pinned at `4db7e43c3d811d84525b3a8bae85b222d6ac89c5`; it is evidence and prior art, not code imported into this proposal. This draft uses the construction in `draft-mih-sokolov-scitt-payload-binding` (Mih and Sokolov; an individual draft, not adopted by the SCITT WG) and the SCITT architecture in RFC 9943. The related `uor-jcs-nfc` work is disclosed above but is not this payload class's digest context.
