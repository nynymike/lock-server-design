# GovOps TRACE Profile — Required Schema Changes

## Purpose

This document lists the **schema changes** the Lock Server GovOps deployment requires on top of the base **TRACE v0.2 Trust Record** (`research/trace-spec.txt`, `schema/trace-claim.json`, EAT profile `tag:agentrust-io.com,2026:trace-v0.2`). The result is a distinct, versioned Jans profile:

```
eat_profile: tag:jans.io,2026:trace-v1
```

It is a **separate EAT profile**, not a fork of the base schema: a verifier declares which profiles it accepts (TRACE v0.2 §3.3), and GovOps records declare this one. The base v0.2 record answers "a workload, in an attested runtime, under a policy, emitted this." GovOps additionally needs to answer **what capability was authorized, by which PDP, under what token context, who enforced it, what effect followed, and how those records chain and correlate into one governed execution** — none of which the flat v0.2 record carries. Everything below is the delta needed for that.

Each change is marked:

- **[STRUCT]** structural change to the envelope,
- **[ADD]** a new field/object the profile adds,
- **[CONSTRAIN]** a tightening of a base field,
- **[LOCK-DERIVED]** explicitly **not** a producer-signed schema change — Lock computes it and stores it outside the signed assertion (listed so implementers do not add it to the record schema).

For the full semantics of every field, `design.md` is authoritative; this document is the schema-change checklist.

---

## 1. Envelope restructuring

**[STRUCT] GovOps nests the TRACE claims under a `trace` object and adds a producer-chain envelope around it.** The base v0.2 record is flat (all claims top-level). The GovOps record separates **the producer-signed claim** (`trace`) from **the envelope that chains and attributes it**:

| Top-level field | Change | Notes |
|---|---|---|
| `producer` | **[ADD]** | Stable logical producer id (e.g. `cedarling-fleet-1`), **not** `name/semver`. Must be byte-equal to `producer_chain.producer_id`. |
| `record_id` | **[ADD]** | Producer-generated UUID/ULID. With `producer_id` + `evidence_domain_id` forms the storage primary key. (v0.2 has no record identity field.) |
| `kid` | **[ADD]** | Selector for the registered verification key (resolved out-of-band from the Producer Key Registry, not from the body). |
| `trace` | **[STRUCT]** | Object wrapping the TRACE claim (fields in §2–§4). The base v0.2 top-level claim fields move inside it. |
| `producer_chain` | **[ADD]** | Per-producer hash chain (§5). |
| `parent_record_ids` | **[ADD]** | Typed causal edges to other records (§6). |
| `signature` | **[CONSTRAIN]** | As v0.2 (base64url Ed25519/ES256/ES384 over RFC 8785 JCS of all fields except `signature`), but the GovOps MVP fixes **Ed25519 only** (a deliberate subset of the v0.2 set). The signature covers the whole envelope, not just `trace`. |

**[CONSTRAIN] `cnf` is not carried in the body.** v0.2 carries the signing key in `cnf.jwk`. GovOps resolves the key by `kid` from the administratively-provisioned Producer Key Registry and **omits `cnf`** — the in-record key is never trusted to establish its own authority. (This is a profile divergence, documented in `design.md`: Alignment with TRACE v0.2.)

---

## 2. `trace` object — top-level claim fields

Inside `trace`, relative to the base v0.2 claim:

| Field | Change | Notes |
|---|---|---|
| `eat_profile` | **[CONSTRAIN]** | Fixed to `tag:jans.io,2026:trace-v1`. |
| `event_kind` | **[ADD]** | **The schema discriminator.** Required; selects which `event` sub-schema applies (§7). This is the single largest addition — v0.2 has no event-kind concept. |
| `signed_at` | **[CONSTRAIN]** | NumericDate; the base v0.2 `iat`, renamed and explicitly "producer time, not receipt time." |
| `trace_execution_id` | **[ADD]** | Governed-execution correlation id. Required for the MVP catalog kinds. |
| `execution_authority` | **[ADD]** | Scopes `trace_execution_id`; travels with it. Distinct from `subject.workload_id`. |
| `execution_epoch_id` / `previous_epoch_id` | **[ADD]** | Epoch rollover within one execution (same `trace_execution_id`). |
| `parent_execution_id` | **[ADD]** | Links a child execution to its parent (delegation/fan-out). |
| `operation_ids` | **[ADD]** | Business operation/transaction ids within the execution. |
| `session_id` / `session_issuer` | **[ADD]** | Optional human-session correlation; `session_issuer` scopes `session_id`. |
| `subject` | **[STRUCT/CONSTRAIN]** | Expanded from the base `subject` string (SPIFFE/DID) into an object (§3). |
| `event` | **[ADD]** | Event-kind-specific payload (§7–§8). |
| `policy` | **[CONSTRAIN]** | Extended (§4). |
| `runtime` | **[CONSTRAIN]** | `pdp_id` required for decision records; otherwise as v0.2. |
| `model` | **[CONSTRAIN]** | Base v0.2 `model` is required; in GovOps it is optional/omitted for non-model producers (PDP/PEP/identity), which do not run a model. |
| `evidence_origin` / `measurement_point` | **[ADD]** | Producer's signed declaration of how it obtained the evidence (maps to v0.2 `origin`; see Alignment). Input to Lock's trust-tier derivation. |
| `recorder` | **[ADD]** | Optional observer party distinct from the actor. |
| `attestation_ref` | **[ADD]** | Optional structured RATS binding (producer claim; input to trust tier). |
| `workload_authentication` | **[ADD]** | Optional: how the workload authenticated (`authentication_layer`/`method`/`authenticated_workload_id`/`proof_ref`). |

---

## 3. `subject` object

**[STRUCT]** v0.2's `subject` is a single SPIFFE/DID string. GovOps makes it an object:

| Field | Change | Notes |
|---|---|---|
| `workload_id` | **[ADD]** | Stable agent/workload identity (SPIFFE URI/WIMSE URI/DID), scoped by `trust_domain`. The base v0.2 `subject` string maps here. Required on `AUTHORIZATION_DECISION`/`CAPABILITY_INVOKED`. |
| `workload_instance_id` | **[ADD]** | The **subject** workload's attested runtime instance — distinct from the producer/PDP instance (`producer_chain.producer_instance_id`). Optional. |
| `human_sponsor` | **[ADD]** | The authenticated human, when present. |
| `delegating_org` | **[ADD]** | Organization for a B2B-delegated agent. |

---

## 4. `policy` object

| Field | Change | Notes |
|---|---|---|
| `bundle_hash` | **[CONSTRAIN]** | As v0.2 (`sha256:` of the Cedar bundle). |
| `policy_store_id` / `policy_store_version` | **[ADD]** | AuthZEN Policy Store identity/version — the keys Lock resolves `capability_id` against (§9). |
| `policy_language` / `policy_language_version` | **[ADD]** | e.g. `cedar` / `4.4.0`. |
| `enforcement_mode` | **[ADD, candidate]** | Adopt the v0.2 set (`enforce`/`advisory`/`silent`/`declared`) so a declared-but-unevaluated policy is representable honestly. Flagged in Alignment as a candidate; required if GovOps must distinguish enforced from declared. |

---

## 5. `producer_chain` object — **[ADD]** (whole object new)

Per-producer, append-only hash chain. No v0.2 equivalent.

| Field | Notes |
|---|---|
| `producer_id` | Byte-equal to top-level `producer`. |
| `producer_instance_id` | The producer/PDP instance (e.g. Cedarling `pdp_id`). |
| `producer_chain_id` | Stable per-chain id; a producer instance may own several concurrent chains. |
| `sequence_number` | Monotonic within one chain. |
| `prev_record_hash` | `content_digest` of the positional predecessor; genesis sentinel on an authenticated genesis. |
| `chain_link` | Present only on a genesis that continues a prior chain (`prev_producer_chain_id`/head/digest/final-sequence). |

**[CONSTRAIN] `producer_version`** (software version/build/runtime) travels as a separate signed field, never folded into `producer_id`.

---

## 6. `parent_record_ids` array — **[ADD]**

Typed causal edges. Each entry: `{ producer_id, record_id, relationship_type }` where `relationship_type` is an **open registry** (`issued_token`, `authorized`, `triggered`, `produced_effect`, `correlates_with`, …). `producer_id` is required on every entry (a bare `record_id` is not globally unique). This is the GovOps analogue of v0.2's `references[]` rel-registry (see Alignment), used for cross-producer causal linkage.

---

## 7. Event-kind discriminator and catalog — **[ADD]**

**[ADD] `trace.event_kind` makes the record a discriminated union**, with `trace.event` validated against the kind's sub-schema and fields-not-applicable-to-the-kind rejected. This is the central GovOps schema change. The catalog:

**MVP catalog (3 kinds):** `AUTHORIZATION_DECISION`, `CAPABILITY_INVOKED`, `RUNTIME_EFFECT`.

**Full-design catalog (adds, deferred past the MVP):** `AUTHENTICATION_EVENT`, `FIDO_CEREMONY`, `EXECUTION_STARTED` (incl. token-exchange bootstrap form), `EXECUTION_CHECKPOINT`, `EXECUTION_SUSPENDED`, `EXECUTION_COMPLETED`, `EXECUTION_ABANDONED`, `DELEGATION_CREATED`, `TRUST_BOUNDARY_CROSSED`, `AUTHORIZATION_TRANSITION`, `INTENT_RECORDED`, `APPROVAL_GRANTED`, `APPROVAL_DENIED`, `USER_CONFIRMATION_RECORDED`, `STEP_UP_REQUESTED`, `CREDENTIAL_PROVISIONED`, `SECURITY_SIGNAL_RECEIVED`, `REMEDIATION_APPLIED`, `IDENTITY_ROTATED`, `POLICY_CHANGED`, `CORRELATION_ASSERTED`.

A conforming MVP schema need only define the three MVP kinds; the rest are additive and introduced in later phases (see `phased-implementation-plan.md`).

---

## 8. `trace.event` sub-schemas (the GovOps capability-governance core)

The three MVP event payloads — all **[ADD]** (no v0.2 equivalent):

**`AUTHORIZATION_DECISION`**
| Field | Required | Notes |
|---|---|---|
| `outcome` | yes | `ALLOW`/`DENY`. |
| `decisions[]` | yes | Each `{ action, resource_type, outcome }` — the **signed capability facts** (Cedar action + resource type, no resource id). Replaces any signed `capability_id`. |
| `tokens[]` | optional | Token context (§8.1). |
| (`trace.policy`, `trace.runtime.pdp_id`) | yes | Required at the `trace` level for this kind. |
| `request_digest`/`input_digest`/`tool_call_digest` | optional | Operation-binding commitments. |

**`CAPABILITY_INVOKED`**
| Field | Required | Notes |
|---|---|---|
| `invocations[]` | yes | Each `{ action, resource_type }` — the same signed facts for what the enforcement point mediated. |
| `outcome` | yes | `SUCCESS`/`FAILURE` (distinct from the decision's `ALLOW`/`DENY`). |
| `enforcement_point_id` | yes | The PEP/gateway that mediated. Signed by the enforcement point's own key, never the PDP's. |
| `request_digest`/`tool_call_digest`/`result_digest` | optional | Operation binding to the decision and the effect. |

**`RUNTIME_EFFECT`**
| Field | Required | Notes |
|---|---|---|
| `outcome` | yes | The observed effect outcome. |
| result/target id or `result_digest` | SHOULD | So the effect is useful evidence, bound to its invocation. |

### 8.1 `tokens[]` entry — **[ADD]**

`{ issuer, token_type, jti` or `fingerprint }` is the MVP minimum. The full design adds, per entry: `claims_ref`, `act`/`may_act` (RFC 8693), `credential_type`, `audience`, `expiration`, `cnf_key_thumbprint`, and `validation_at_decision` (`signature_check`/`contents_check`/`status_check` + `revocation_freshness`), with a sibling `token_claims[]` carrying `claims_at_decision`. All deferred past the MVP.

---

## 9. Capability resolution — **[LOCK-DERIVED, MVP-REQUIRED]**

`capability_id` is **not** a signed field and must not be added to the record schema. Producers sign `(action, resource_type)` (§8); **Lock MUST resolve `capability_id`** from `(policy_store_id, policy_store_version, action, resource_type)` against a **versioned capability mapping that lives in the policy store** and store the result as `capability_resolution` outside the signed assertion.

**Capability resolution is an MVP requirement, not a deferred one.** The GovOps purpose — analyzing *what business capabilities* are being authorized and invoked, by whom, and at what rate — collapses without it: a raw `(action, resource_type)` pair like `(Acme::Action::"Pay", Acme::Payment)` is a Cedar implementation detail, not a governable business capability. Every MVP `AUTHORIZATION_DECISION` and `CAPABILITY_INVOKED` record Lock ingests MUST have `capability_resolution` attempted; when the mapping has no entry for the signed facts, Lock records `capability_ids: []` with a `resolution_status` of `unmapped` (feeding the "deprecated/unmapped capabilities" metric in §14) rather than silently dropping it.

The one schema-adjacent artifact GovOps adds is that **capability mapping** (an entry list of `{ action, resource_type, capability_id }` with a `mapping_version`), which is policy-store data, not record data. The mapping is the join key into the **capability catalog** (§13.6), which is where the business meaning lives.

---

## 10. Producer Key Registry and authorization statement — **[ADD]** (out-of-band schemas)

Not record fields, but schemas GovOps requires alongside the record:

- **Producer key entry:** `(evidence_domain_id, producer_id, kid)` → `public_key_jwk`, `key_type`, `authorized_event_kinds`, `authorized_measurement_points`, `valid_from`/`valid_until`, `revoked_at`/`revocation_reason`, `key_class`.
- **Producer-Key Authorization Statement:** an administratively-signed artifact binding `statement_id`/`statement_version`, `administrative_issuer`, `evidence_domain_id`, `producer_id`, `public_key_thumbprint`, `kid`, `authorized_event_kinds`/`authorized_measurement_points`, `issued_at`, `valid_from`/`valid_until`, `revocation_status`, `supersedes`, `signature`. Carried in Evidence Packets so offline verifiers can confirm a key's authority.

---

## 11. Receipt commitment — **[ADD]** (Lock-side, separate profile)

Lock's receipt-ledger entry is its own profile (`tag:jans.io,2026:lock-trace-receipt-v1`): `{ receipt_profile, evidence_domain_id, receipt_sequence, received_at (ms precision), producer_id, record_id, content_digest, prev_receipt_hash }`. See `jans-trace-core-mvp-design.md` §7. Not part of the producer record schema.

---

## 12. Explicitly NOT producer-schema changes — **[LOCK-DERIVED]**

Implementers must keep these **out** of the signed record schema; Lock computes and stores them in the three-part Stored Record Envelope (`verification`/`ingestion`) or the append-only assessment store:

- `content_digest`, `receipt_sequence`, `received_at`, `prev_receipt_hash`, and the ingestion flags (`coverage_gap_flag`, `chain_link_failure_flag`, `equivocation_flag`, `late_flag`, `unattributed_flag`, `candidate_flag`).
- The admission results (`key_resolved`/`key_temporally_valid`/`key_not_revoked`/`key_authorized_for_producer`/`producer_authorized_for_claim`), `key_thumbprint`, `key_authorization_ref`, `verified_at`.
- `trust_tier` and the per-dimension verification vector.
- Settlement assessments/receipts, completeness/assurance/lineage results, delegation-validation, instance-binding, external-anchor assessments, and `capability_resolution`.
- `evidence_domain_id` (Lock-derived from the authenticated client; a producer-supplied value is ignored and flagged).

A producer that places any of these in its signed body has that field ignored and the attempt flagged.

---

## 13. Lock-derived analytics enrichment — **[LOCK-DERIVED]**

GovOps is not only evidence preservation; it is **analytics over governed execution**. The signed records say what producers observed; the enrichment below is what Lock *derives* so the records can be aggregated into governance answers ("what share of high-risk capability use was autonomous, by business unit, last quarter?"). Everything in §13 is **[LOCK-DERIVED]** — computed and stored outside the signed assertion, in the assessment store — and must never be added to the producer record schema. Each derived value carries its own **provenance** (what evidence it came from) and, where correlation is involved, an **attribution quality** (§13.8).

A governing principle runs through all of §13: **producers sign facts; Lock derives interpretations.** Token contents, organizational attributes, actor classification, region, and resource sensitivity are interpretations Lock assembles from reference data and correlation — not things a producer asserts about itself.

### 13.1 Token enrichment — producer-signed vs Lock-resolved

A `jti` in a signed record is **only a lookup key**. Lock uses `(issuer, jti)` to correlate against token information the Auth Server retained at issuance: `sub`, `sid`, `client_id`, `azp`, `aud`, `act`, `may_act`, `scope`, `cnf`, token type, issue time (`iat`), expiration (`exp`), and the authentication context. The resolved result is Lock-derived and stored separately from anything the producer signed.

Token information reaches Lock through **two independent paths**, and both are retained with provenance and timestamps because neither is always available:

| Field | Source | When present |
|---|---|---|
| `claims_at_decision` | **Producer-signed.** The subset of claims the PDP saw and signed into `tokens[].token_claims[]` at decision time. | When the producer chose to sign them (full-design `tokens[]`, §8.1). Authoritative for *what the PDP actually acted on*. |
| `current_token_state` | **Lock-resolved.** Looked up later from the Auth Server via `(issuer, jti)`. | When the token is still resolvable (not purged/rotated) and the Auth Server exposes retained claims. Authoritative for *what the token actually was/became*. |

Each path records `{ resolved_from, resolved_at, claims: {...} }` so an analyst can tell a producer-asserted claim from a Lock-correlated one, and can see staleness. When the two disagree (e.g. scope narrowed after issuance), both are kept; the divergence is itself a governance signal. Token lookup is **not** guaranteed — short-lived or purged tokens may be unresolvable — so a record with only `claims_at_decision`, or with neither, is valid and simply carries lower attribution quality (§13.8).

### 13.2 Session and authentication correlation (the `sid` join)

`sid` (resolved via §13.1) is the join key from a machine action back to a human authentication. Lock walks:

```
jti  →  token enrichment (§13.1)  →  sid  →  browser/session record
     →  AUTHENTICATION_EVENT  →  FIDO_CEREMONY
```

The result is stored as a `session_correlation` object: `{ sid, session_issuer, authentication_event_ref, authentication_strength, fido_ceremony_ref, authenticated_human_ref, resolved_via, resolved_at }`. `AUTHENTICATION_EVENT` and `FIDO_CEREMONY` are full-design event kinds (§7); in the MVP the join may terminate at the session record with reduced strength and lower attribution quality. `authentication_strength` (e.g. `phishing_resistant_mfa`, `mfa`, `single_factor`, `unknown`) is derived from the ceremony/event, not asserted by the invoking workload.

### 13.3 `actor_context` — derived, not a subject type

GovOps does **not** model "human vs software" as a subject type on the record (a workload does not know, and must not assert, whether a human is behind it). Lock **derives** `actor_context` from the correlation evidence:

| `actor_context` | Meaning |
|---|---|
| `human_direct` | A human authenticated and the action maps directly to that session. |
| `human_delegated_to_workload` | A human authenticated and delegated to a workload that then acted (`act`/`may_act`, delegation records). |
| `software_autonomous` | A workload acting on its own credential with no human session in the chain. |
| `service_to_service` | One service acting on behalf of another via workload credentials, no human. |
| `unknown` | Correlation evidence insufficient to classify. |

The derivation stores the **evidence used**: `{ actor_context, evidence: [token act/may_act, session_correlation, delegation records, workload_authentication], attribution_quality }`. "Unknown" is a first-class, reportable value — never silently coerced to a human or software bucket.

### 13.4 Organizational reference data (versioned, not copied from tokens)

Organizational attributes (business unit, team, owner) are **never copied blindly from token claims**. Lock resolves the stable identifiers that *are* trustworthy — `sub`, `client_id`, `workload_id`, `resource_id` — through **versioned organizational reference data**, retaining the `mapping_version` and `resolved_at` for every resolution so historical records keep their *effective* classification.

Subject-to-org mappings, each versioned:

| Stable id | Resolves to |
|---|---|
| human `sub` | business unit, team |
| `client_id` | owning application / service, service owner |
| `workload_id` | owning application, team, business unit |
| `capability_id` | capability owner, business function (via the catalog, §13.6) |
| target `resource_id` | owning business unit, region |

Stored as `org_resolution: { sub_ref → {business_unit, team}, client_id → {app, owner}, workload_id → {app, team, business_unit}, mapping_version, resolved_at }`. Exact identifiers that are sensitive are referenced by access-controlled hash, not value.

### 13.5 The four meanings of "region"

"Region" is ambiguous and GovOps separates it into four distinct dimensions, each with its own source and confidence/provenance:

| Region dimension | Meaning | Typical source |
|---|---|---|
| `human_region` | Where the human / their session originated | `session_correlation`, auth event geo |
| `workload_region` | Where the acting workload executed | workload attestation / runtime |
| `enforcement_region` | Where the enforcement point (PEP) ran | `enforcement_point_id` → PEP registry |
| `target_region` | Where the target resource / data lives | target-resource classification (§13.6) |

Each is stored as `{ value, source, confidence }`. They are reported separately — "cross-region use" (§14) is defined over a *specific pair* of these, never a collapsed single "region".

### 13.6 Target-resource classification and the capability catalog

Two versioned reference datasets give business meaning to the signed facts:

**Target-resource classification** (keyed by resolved `resource_id`): `{ resource_domain, resource_owner, business_unit, data_classification, deployment_region, criticality }`. Exact resource identifiers are hashed / access-controlled; the classification is what analytics use.

**Capability catalog** (keyed by `capability_id` from §9): `{ business_owner, business_function, risk_tier, data_sensitivity, regulated_scope, allowed_regions, expected_producer_roles, lifecycle_status }`. This is where a resolved `capability_id` becomes a governable business capability — `lifecycle_status` (e.g. `active`/`deprecated`/`retired`) and `expected_producer_roles` feed the §14 hygiene metrics.

### 13.7 Effective (versioned) vs current classification

Trend analysis uses the classification that was **effective at event time** — the `mapping_version` resolved against the org/catalog/resource data as it stood then — **not** today's org chart. A capability moved between business units last month must still count under its *then-current* unit for any period before the move. Lock additionally MAY compute an optional **"current org" view** that re-resolves every historical event through today's reference data, for "where would this land under the current structure?" questions. Both are derived; the effective view is the default and the current view is explicitly labelled.

### 13.8 Attribution quality

Every derived correlation (token, session, actor_context, org, region) carries an **attribution quality** so aggregates can be filtered or confidence-weighted:

| Quality | Meaning |
|---|---|
| `verified` | Backed by cryptographic/attested evidence (e.g. FIDO ceremony, attested token). |
| `correlated` | Joined through a reliable key (e.g. `(issuer, jti)` → `sid` → session) with no contradiction. |
| `asserted` | Taken from a producer-signed claim without independent corroboration. |
| `ambiguous` | Multiple candidate resolutions; recorded with the alternatives. |
| `unknown` | No usable evidence. |

### 13.9 Per-invocation analytics projection

For each `CAPABILITY_INVOKED`, Lock materializes a flat **analytics projection** combining the signed facts with all of §13's derivations, so GovOps queries do not re-walk the graph:

```json
{
  "capability_id": "invoke:payment-authorization",
  "invoked_at": "2026-06-11T00:41:03.004Z",
  "actor_context": "human_delegated_to_workload",
  "human_subject_ref": "sha256:...",
  "workload_id": "spiffe://example.org/agent/planner",
  "business_unit": "retail-payments",
  "workload_region": "eu-west-1",
  "target_region": "eu-west-1",
  "resource_data_class": "confidential",
  "authentication_strength": "phishing_resistant_mfa",
  "attribution_quality": "correlated"
}
```

The projection records the **effective** (§13.7) classification; its `attribution_quality` is the weakest of the correlations that fed it.

---

## 14. GovOps metrics — definitions and denominators — **[LOCK-DERIVED]**

Metrics are computed over the §13.9 projections and the signed records. The central rule: **state the denominator explicitly, and never mix event kinds in one ratio.** Three families of events answer three different questions and MUST be reported separately:

- **Authorization** metrics count `AUTHORIZATION_DECISION` records (what the PDP *allowed/denied*).
- **Invocation** metrics count `CAPABILITY_INVOKED` records (what an enforcement point *actually mediated*).
- **Observed-effect** metrics count `RUNTIME_EFFECT` records (what effect *actually followed*).

"Percentage of actions by humans versus software" is an **invocation** metric: its denominator is the count of `CAPABILITY_INVOKED` records (optionally scoped to a capability/BU/period), **not** authorization decisions and **not** a blend. A decision that was allowed but never invoked does not count as an "action."

Useful GovOps metrics (all over the invocation denominator unless noted), each filterable by effective BU/region/capability/period:

1. **Human-direct share** — `actor_context = human_direct` ÷ invocations.
2. **Human-delegated share** — `actor_context = human_delegated_to_workload` ÷ invocations.
3. **Autonomous share** — `actor_context ∈ {software_autonomous, service_to_service}` ÷ invocations.
4. **Invocations by business unit / by region** — counts grouped by effective `business_unit` and by each region dimension (§13.5), reported per-dimension.
5. **Fastest-growing capabilities** — invocation-count growth per `capability_id` across periods.
6. **Change in autonomous activity** — period-over-period delta of metric 3.
7. **High-risk capability use without strong auth** — invocations where catalog `risk_tier` is high and `authentication_strength` is weak/`unknown` ÷ high-risk invocations.
8. **Cross-region use** — invocations where a *named pair* of region dimensions differ (e.g. `human_region ≠ target_region`); reported per pair, never collapsed.
9. **Authorized-but-never-invoked** — `AUTHORIZATION_DECISION`(ALLOW) with no correlated `CAPABILITY_INVOKED` ÷ allowed decisions. *(Authorization denominator.)*
10. **Invocations lacking a runtime effect** — `CAPABILITY_INVOKED`(SUCCESS) with no correlated `RUNTIME_EFFECT` ÷ successful invocations.
11. **Unknown sponsor / unknown owner** — invocations where `actor_context = unknown`, or `capability_id` has no catalog `business_owner` ÷ invocations.
12. **Deprecated / unmapped capability use** — invocations whose `capability_id` is catalog-`deprecated`/`retired`, plus resolutions with `resolution_status = unmapped` (§9) ÷ invocations.

Metrics 1–3 and 11 may be reported with an **attribution-quality cut** (e.g. counting only `verified`/`correlated`), and SHOULD state which quality threshold was applied so a reader knows whether an "autonomous share" is measured or inferred.

---

## Summary of required schema changes

| # | Change | Class | MVP? |
|---|---|---|---|
| 1 | Nest TRACE claim under `trace`; add `producer`/`record_id`/`kid`/`producer_chain`/`parent_record_ids` envelope | STRUCT | yes |
| 2 | Drop `cnf` from the body (key resolved by `kid`) | CONSTRAIN | yes |
| 3 | Add `event_kind` discriminator + `trace.event` union | ADD | yes |
| 4 | Expand `subject` string → object (`workload_id`/`workload_instance_id`/`human_sponsor`/`delegating_org`) | STRUCT | yes |
| 5 | Add execution-correlation fields (`trace_execution_id`/`execution_authority`/epoch/parent/operation/session) | ADD | yes |
| 6 | Extend `policy` (store id/version, language) ; `enforcement_mode` candidate | ADD | yes (mode: candidate) |
| 7 | Add `producer_chain` + `parent_record_ids` (hash chain + causal edges) | ADD | yes |
| 8 | MVP `event` payloads: `decisions[]`/`invocations[]`/effect outcome (signed `(action, resource_type)`) | ADD | yes |
| 9 | Full token context (`validation_at_decision`, `token_claims[]`, credential metadata) | ADD | later |
| 10 | Lifecycle/identity/approval/signal event kinds (21 more) | ADD | later |
| 11 | Capability resolution (policy-store mapping; `capability_id` Lock-derived, resolution MVP-required) | ADD / LOCK-DERIVED | yes |
| 12 | Producer Key Registry entry + Producer-Key Authorization Statement schemas | ADD (out-of-band) | yes |
| 13 | Receipt-commitment profile | ADD (Lock-side) | yes |
| 14 | Capability resolution (every MVP decision/invocation record) | LOCK-DERIVED | **yes** |
| 15 | Analytics enrichment: token (`claims_at_decision` vs `current_token_state`), `session_correlation`, `actor_context`, versioned org/resource/capability reference data, four region dimensions, attribution quality, per-invocation projection | LOCK-DERIVED | yes (full depth phased) |
| 16 | GovOps metrics with explicit per-family denominators (authorization / invocation / observed-effect) | LOCK-DERIVED | yes |

## References

- `design.md` — authoritative field semantics, event-kind schemas, Lock-derived enrichment and assessment-store layout, GovOps analytics/metrics, and Alignment with TRACE v0.2.
- `Lock-Server-TRACE-MVP-Design.md` — the MVP wire shape and required/deferred boundary.
- `jans-trace-core-mvp-design.md` — signing scope, canonicalization, and the receipt-commitment profile.
- `research/trace-spec.txt` — the base TRACE v0.2 Trust Record schema this profile extends.

---

## Non-normative example

> **Non-normative.** This section illustrates the schema changes above with a worked example. It adds no requirement; where it and `design.md` could differ, `design.md` governs. Values are illustrative and abbreviated (`...`).

### A. Base TRACE v0.2 record (for contrast)

The base schema is flat, model-centric, and has no event kind, execution correlation, or chaining:

```json
{
  "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
  "iat": 1781138542,
  "subject": "spiffe://trust.example.org/agent/payments-processor/prod",
  "model": { "provider": "example-provider", "model_id": "example-model-1", "version": "20251001" },
  "runtime": { "platform": "software-only", "measurement": "sha256:..." },
  "policy": { "bundle_hash": "sha256:...", "enforcement_mode": "enforce" },
  "data_class": "confidential",
  "tool_transcript": { "hash": "sha256:...", "call_count": 3 },
  "build_provenance": { "slsa_level": 2, "digest": "sha256:..." },
  "appraisal": { "status": "none", "verifier": "https://verifier.example.org" },
  "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." } },
  "signature": "base64url(...)"
}
```

### B. GovOps `AUTHORIZATION_DECISION` (the profile applied)

The same decision as a GovOps record: claims nested under `trace`, an `event_kind` discriminator, the signed capability **facts** in `decisions[]` (no `capability_id`), execution correlation, the producer-chain envelope, and a typed causal edge to the Auth Server's token-issuance record. The signing key is referenced by `kid` and resolved out-of-band — there is no `cnf` in the body.

```json
{
  "producer": "cedarling-fleet-1",
  "record_id": "9f3e9e2a-6b0e-4b2c-9f6e-3a2f7b0c9d41",
  "kid": "key-2026-01",
  "trace": {
    "eat_profile": "tag:jans.io,2026:trace-v1",
    "event_kind": "AUTHORIZATION_DECISION",
    "signed_at": 1781138542,
    "trace_execution_id": "exec-01JABCXYZQK8P5N9F2C7R3T4V6",
    "execution_authority": "spiffe://example.org/agent/planner",
    "subject": {
      "workload_id": "spiffe://example.org/agent/planner",
      "workload_instance_id": "04bbe9ef-a853-417c-a2b8-5328b62936e2"
    },
    "evidence_origin": "directly_observed",
    "measurement_point": "cedarling-pdp-in-process",
    "event": {
      "outcome": "ALLOW",
      "decisions": [
        { "action": "Acme::Action::\"Pay\"", "resource_type": "Acme::Payment", "outcome": "ALLOW" }
      ],
      "tokens": [
        { "issuer": "https://accounts.example.org", "token_type": "access_token", "jti": "9c9f2e77-..." },
        { "issuer": "https://accounts.example.org", "token_type": "id_token", "jti": "a1b2c3d4-..." },
        { "issuer": "https://accounts.example.org", "token_type": "transaction_token", "jti": "7e5f0a21-..." },
        { "issuer": "https://workload-ca.example.org", "token_type": "workload_credential", "fingerprint": "sha256:cert-..." },
        { "issuer": "https://attestation.example.org", "token_type": "attestation_token", "jti": "c0ffee11-..." }
      ]
    },
    "policy": {
      "bundle_hash": "sha256:...",
      "policy_store_id": "https://example.org/policy-stores/payments",
      "policy_store_version": "1.2.3",
      "policy_language": "cedar",
      "policy_language_version": "4.4.0"
    },
    "runtime": { "pdp_id": "cedarling-001" }
  },
  "producer_chain": {
    "producer_id": "cedarling-fleet-1",
    "producer_instance_id": "cedarling-001",
    "producer_chain_id": "chain-01JABC9Z0K",
    "sequence_number": 4821,
    "prev_record_hash": "sha256:..."
  },
  "parent_record_ids": [
    { "producer_id": "jans-auth-server", "record_id": "R-token-issued-001", "relationship_type": "issued_token" }
  ],
  "signature": "base64url(Ed25519 over RFC 8785 JCS of all fields except signature)"
}
```

Changes visible here, keyed to the sections above: envelope restructuring (§1), the `trace` object and `event_kind` (§2, §7), the `subject` object (§3), execution-correlation fields (§2/§5-correlation), the extended `policy` (§4), `producer_chain` (§5), `parent_record_ids` (§6), and the signed `decisions[]` capability facts (§8). No `cnf` (§1). No `capability_id` anywhere in the signed body (§9).

### C. The Lock-derived data for that record (stored outside the signed assertion)

Everything Lock computes lives in the Stored Record Envelope's `verification`/`ingestion` parts and the assessment store — **never** inside `trace`. For the record above:

```json
{
  "verification": {
    "signature_valid": true,
    "key_id": "key-2026-01",
    "key_thumbprint": "sha256:...",
    "verified_at": "2026-06-11T00:41:02.123Z",
    "algorithm": "Ed25519",
    "key_resolved": "valid",
    "key_temporally_valid": "valid",
    "key_not_revoked": "valid",
    "key_authorized_for_producer": "valid",
    "producer_authorized_for_claim": "valid",
    "key_authorization_ref": { "statement_id": "pkauth-01JABEF7Q2", "statement_version": 3, "public_key_thumbprint": "sha256:..." },
    "trust_tier": "attested"
  },
  "ingestion": {
    "receipt_sequence": 108422,
    "received_at": "2026-06-11T00:41:02.123Z",
    "prev_receipt_hash": "sha256:...",
    "coverage_gap_flag": false,
    "chain_link_failure_flag": false,
    "equivocation_flag": false,
    "late_flag": false
  },
  "capability_resolution": {
    "capability_ids": ["invoke:payment-authorization"],
    "resolution_status": "resolved",
    "policy_store_id": "https://example.org/policy-stores/payments",
    "policy_store_version": "1.2.3",
    "mapping_version": "3",
    "resolved_at": "2026-06-11T00:41:02.123Z"
  },
  "token_enrichment": [
    {
      "issuer": "https://accounts.example.org",
      "jti": "9c9f2e77-...",
      "token_type": "access_token",
      "claims_at_decision": {
        "resolved_from": "producer_signed",
        "resolved_at": "2026-06-11T00:41:02.000Z",
        "claims": { "sub": "sha256:user-...", "sid": "sess-7f3a...", "client_id": "planner-app", "azp": "planner-app", "scope": "payments.write", "act": { "sub": "spiffe://example.org/agent/planner" } }
      },
      "current_token_state": {
        "resolved_from": "auth_server_lookup",
        "resolved_at": "2026-06-11T00:41:05.400Z",
        "claims": { "sub": "sha256:user-...", "sid": "sess-7f3a...", "client_id": "planner-app", "aud": "payments-api", "scope": "payments.write", "iat": 1781138500, "exp": 1781142100, "cnf": { "jkt": "sha256:..." }, "may_act": { "sub": "spiffe://example.org/agent/planner" } }
      }
    }
  ],
  "session_correlation": {
    "sid": "sess-7f3a...",
    "session_issuer": "https://accounts.example.org",
    "authentication_event_ref": "R-authn-event-88",
    "authentication_strength": "phishing_resistant_mfa",
    "fido_ceremony_ref": "R-fido-ceremony-88",
    "authenticated_human_ref": "sha256:user-...",
    "resolved_via": "jti->sid->session->authn_event->fido_ceremony",
    "resolved_at": "2026-06-11T00:41:05.600Z"
  },
  "actor_classification": {
    "actor_context": "human_delegated_to_workload",
    "evidence": ["token.act", "token.may_act", "session_correlation", "fido_ceremony_ref"],
    "attribution_quality": "correlated"
  },
  "org_resolution": {
    "mapping_version": "org-2026-05",
    "resolved_at": "2026-06-11T00:41:05.700Z",
    "sub_ref": { "business_unit": "retail-payments", "team": "payments-core" },
    "client_id": { "app": "planner-app", "owner": "sha256:owner-..." },
    "workload_id": { "app": "planner", "team": "automation", "business_unit": "retail-payments" }
  },
  "region_resolution": {
    "human_region": { "value": "eu-west-1", "source": "authn_event_geo", "confidence": "high" },
    "workload_region": { "value": "eu-west-1", "source": "workload_attestation", "confidence": "high" },
    "enforcement_region": { "value": "eu-west-1", "source": "pep_registry", "confidence": "high" },
    "target_region": { "value": "eu-west-1", "source": "resource_classification", "confidence": "medium" }
  },
  "target_resource_classification": {
    "resource_ref": "sha256:resource-...",
    "resource_domain": "payments",
    "resource_owner": "sha256:owner-...",
    "business_unit": "retail-payments",
    "data_classification": "confidential",
    "deployment_region": "eu-west-1",
    "criticality": "high"
  },
  "capability_catalog_resolution": {
    "capability_id": "invoke:payment-authorization",
    "business_owner": "sha256:owner-...",
    "business_function": "payment-authorization",
    "risk_tier": "high",
    "data_sensitivity": "confidential",
    "regulated_scope": ["PCI-DSS"],
    "allowed_regions": ["eu-west-1"],
    "expected_producer_roles": ["pdp", "payments-enforcement-point"],
    "lifecycle_status": "active"
  }
}
```

This is the point of §9 and §12: `capability_id`, `trust_tier`, the admission results, the receipt metadata, **and every §13 enrichment** are all **here**, not in the producer's signed record. The token enrichment keeps both the producer-signed `claims_at_decision` and the later Lock-resolved `current_token_state` with their own provenance and timestamps (§13.1); the `sid` resolved from the token joins the action back through the session to the FIDO ceremony (§13.2); `actor_context` is *derived* from that evidence, not asserted by the workload (§13.3); organization, region, resource, and capability meaning come from versioned reference data (§13.4–§13.6); and each correlation carries an attribution quality (§13.8). A producer that tried to sign any of them would have the field ignored and the attempt flagged.

### D. The paired `CAPABILITY_INVOKED` (enforcement-point separation)

The enforcement point — a **different producer** with its own key and chain, even if co-located with Cedarling — signs the invocation, carrying the same signed `(action, resource_type)` facts in `invocations[]` and an `authorized` edge back to the decision:

```json
{
  "producer": "payments-gateway",
  "record_id": "R-capability-invoked-003",
  "kid": "gw-key-2026-01",
  "trace": {
    "eat_profile": "tag:jans.io,2026:trace-v1",
    "event_kind": "CAPABILITY_INVOKED",
    "signed_at": 1781138543,
    "trace_execution_id": "exec-01JABCXYZQK8P5N9F2C7R3T4V6",
    "execution_authority": "spiffe://example.org/agent/planner",
    "subject": { "workload_id": "spiffe://example.org/agent/planner" },
    "event": {
      "outcome": "SUCCESS",
      "invocations": [ { "action": "Acme::Action::\"Pay\"", "resource_type": "Acme::Payment" } ],
      "enforcement_point_id": "payments-gateway-01"
    }
  },
  "producer_chain": {
    "producer_id": "payments-gateway",
    "producer_instance_id": "gw-01",
    "producer_chain_id": "chain-gw-01JABD",
    "sequence_number": 991,
    "prev_record_hash": "sha256:..."
  },
  "parent_record_ids": [
    { "producer_id": "cedarling-fleet-1", "record_id": "9f3e9e2a-6b0e-4b2c-9f6e-3a2f7b0c9d41", "relationship_type": "authorized" }
  ],
  "signature": "base64url(...)"
}
```

The decision (`cedarling-fleet-1`) and the invocation (`payments-gateway`) are **separate producers with separate keys**, correlated by the shared `trace_execution_id` and linked by the `authorized` edge — the enforcement-point separation of §8. Lock resolves `capability_id` for *both* records from their signed `(action, resource_type)` and can compare them across the edge; neither record carries a producer-signed `capability_id`.

### E. The Lock-derived analytics projection and the GovOps view

From the enrichment in C, Lock materializes the flat per-invocation projection (§13.9) for the `CAPABILITY_INVOKED` of D — the row GovOps queries actually aggregate:

```json
{
  "capability_id": "invoke:payment-authorization",
  "invoked_at": "2026-06-11T00:41:03.004Z",
  "actor_context": "human_delegated_to_workload",
  "human_subject_ref": "sha256:user-...",
  "workload_id": "spiffe://example.org/agent/planner",
  "business_unit": "retail-payments",
  "workload_region": "eu-west-1",
  "target_region": "eu-west-1",
  "resource_data_class": "confidential",
  "authentication_strength": "phishing_resistant_mfa",
  "attribution_quality": "correlated"
}
```

The classification here is the one **effective at `invoked_at`** (`org-2026-05`, catalog `active`), per §13.7 — if `retail-payments` is later reorganized, this invocation still counts under `retail-payments` for any period before the move. A separate, explicitly-labelled "current org" view may re-resolve it under today's structure.

Reading this through §14: this one invocation contributes to the **invocation** denominator (not authorization), lands in the `human_delegated_to_workload` share (metric 2), the `retail-payments` BU and `eu-west-1` region cuts (metric 4), and — because catalog `risk_tier` is `high` and the authentication was `phishing_resistant_mfa` — it does **not** count toward "high-risk without strong auth" (metric 7). Its `attribution_quality` of `correlated` means it survives a `verified`/`correlated` quality cut. The paired decision in B is counted only in authorization metrics; the two are never blended into one ratio.

