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

## 9. Capability resolution — **[LOCK-DERIVED]** (not a record-schema change)

`capability_id` is **not** a signed field and must not be added to the record schema. Producers sign `(action, resource_type)` (§8); Lock resolves `capability_id` from `(policy_store_id, policy_store_version, action, resource_type)` against a **versioned capability mapping that lives in the policy store** and stores the result as `capability_resolution` outside the signed assertion. The one schema-adjacent artifact GovOps adds is that **capability mapping** (an entry list of `{ action, resource_type, capability_id }` with a `mapping_version`), which is policy-store data, not record data.

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
| 11 | Capability mapping (policy-store data; `capability_id` is Lock-derived, not a record field) | ADD / LOCK-DERIVED | later |
| 12 | Producer Key Registry entry + Producer-Key Authorization Statement schemas | ADD (out-of-band) | yes |
| 13 | Receipt-commitment profile | ADD (Lock-side) | yes |

## References

- `design.md` — authoritative field semantics, event-kind schemas, and Alignment with TRACE v0.2.
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
        { "issuer": "https://accounts.example.org", "token_type": "access_token", "jti": "9c9f2e77-..." }
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
    "policy_store_id": "https://example.org/policy-stores/payments",
    "policy_store_version": "1.2.3",
    "mapping_version": "3",
    "resolved_at": "2026-06-11T00:41:02.123Z"
  }
}
```

This is the point of §9 and §12: `capability_id`, `trust_tier`, the admission results, and the receipt metadata are all **here**, not in the producer's signed record. A producer that tried to sign any of them would have the field ignored and the attempt flagged.

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
