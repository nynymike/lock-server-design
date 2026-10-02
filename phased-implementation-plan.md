# TRACE Phased Implementation Plan

TRACE is implemented incrementally. Each phase builds on the same signed-record model, so an MVP delivers useful evidence without requiring every assurance feature at launch. The phase boundaries below are reconciled with the current scope of `Lock-Server-TRACE-MVP-Design.md` (Phase 1 = the MVP) and `design.md` (the full design). Where this plan and those documents could drift, those documents are authoritative.

Each phase preserves backward compatibility with previously accepted records. Advanced features strengthen the evidence and its assurance level; they never change or rewrite the original signed assertions.

## Phase 1 — MVP Evidence Collection

The essential TRACE foundation (the full scope of `Lock-Server-TRACE-MVP-Design.md`):

- **Signed record ingestion**, both single-record (`POST /api/v1/audit/trace`) and **bulk** (`POST /api/v1/audit/trace/bulk`, one producer per batch, per-record accept/reject) — bulk is in the MVP because a high-throughput producer such as Cedarling can make thousands of decisions per second.
- **Administrative producer-key registration** — keys provisioned through Lock configuration or an admin API under a separate scope, scoped by `authorized_event_kinds`; never registered implicitly from a submitted record. Admission runs the key-state checks (`key_resolved`, `key_temporally_valid`, `key_not_revoked`, `key_authorized_for_producer`, `producer_authorized_for_claim`) and records their results immutably in the `verification` envelope.
- **Lock-derived evidence-domain isolation** — `evidence_domain_id` derived from the authenticated submitting client, never from the record body.
- **Signature, identity, and schema validation** — Ed25519 over RFC 8785 (JCS) canonical bytes, `kid`-selected key, and the admission gates `signature_valid` and `identity_sound`.
- **Immutable preservation of producer assertions** — the signed `assertion` is byte-immutable; all Lock-derived data lives outside it.
- **Producer-chain sequencing and predecessor validation** — `producer_chain_id` / `sequence_number` / `prev_record_hash`, one or more chains per producer instance (so concurrent writers need not share one sequence allocator), with `first_observed` genesis acceptable.
- **A Lock receipt hash chain** — the tamper-evident, per-evidence-domain ingestion ledger (`receipt_sequence` / `received_at` at millisecond precision / `prev_receipt_hash`), assigned atomically with each accepted record.
- **Integrity flagging at ingestion** — **coverage-gap, chain-link-failure, equivocation, and late-arrival** flagging. Each is surfaced, never silently dropped or silently resolved.
- **Correlation** by `(evidence_domain_id, execution_authority, trace_execution_id)`, required at ingestion (no unattributed-evidence/backfill path in the MVP).
- **Signed capability facts** — `AUTHORIZATION_DECISION` signs `decisions[]` (`{action, resource_type, outcome}`) and `CAPABILITY_INVOKED` signs `invocations[]` (`{action, resource_type}`); the `capability_id` governance label is Lock-derived and its resolution/index are deferred.
- **Retrieval by record and execution.** Capability, workload, session, transaction, and token retrieval (and the corresponding indexes) are deferred.
- **Structured errors and idempotent replay.**

This phase provides attributable, tamper-evident evidence that can be correlated across producers, with ingestion-time integrity findings visible.

> Note on the receipt layer: the **receipt hash chain** is Phase 1. What is deferred to Phase 2 is the **signed receipt checkpoint** over that chain (the independently-verifiable, externally-anchorable commitment) — not the ledger itself.

## Phase 2 — Settlement and Ledger Integrity

Add the Lock-attested assessment layer over the Phase 1 ledger:

- **Lock-signed settlement assessments** and the per-record settlement lifecycle (`submitted` → `settled`) over the six settlement checks, with the first pass synchronous and **asynchronous re-settlement** as later evidence arrives.
- **Signed receipt checkpoints** over the receipt ledger (distinct from the Phase 1 ledger itself), using a Lock-owned ledger-signing key.
- **Key rotation and revocation handling** beyond basic validity — rotation-overlap selection by `kid`, and the TRACE v0.2 §3.2.3 revocation rule (order an anchored record by SCITT inclusion entry ID against `last_valid_entry_id`; otherwise reject all records from the revoked key), with historical results immune to later revocation.
- **Trust-tier assignment** and the per-dimension verification vector (Lock-assigned, never producer-declared).

This phase lets Lock distinguish a *submitted claim* from *evidence it has independently validated and settled*. (Equivocation detection and coverage-gap/late-arrival reporting are **not** here — they are Phase 1.)

## Phase 3 — Completeness and Context

Add the context and completeness layer:

- **Evidence-expectation profiles** and **execution completeness assessments** (including the AIMS evidence-completeness profile), making missing evidence visible as `expected_evidence_missing`.
- **Capability resolution** — Lock resolving `capability_id` from the signed `(action, resource_type)` + policy-store mapping, and the capability index / capability retrieval.
- **Token enrichment** and **decision-time token-validation evidence** (`validation_at_decision`, `revocation_freshness`, `token_claims[]`), and token-exchange / transaction-token lineage.
- **Operation-binding commitments** (`request_digest` / `tool_call_digest` / `result_digest`, and proof-of-possession `pop_binding`).
- **Evidence-origin classification** (`evidence_origin` / `measurement_point` / `recorder`) and the richer retrieval dimensions (workload, session, transaction, token).
- **Disconnected candidate-record handling** (`candidate_flag`) and late-arrival correlation, including `CORRELATION_ASSERTED` backfill of previously-unattributed evidence.

This phase connects authorization decisions to capability invocations and runtime effects, and makes absent evidence explicit rather than assumed.

## Phase 4 — Full Assurance

Implement end-to-end provenance and the highest-assurance features:

- **Delegation non-expansion validation** (child authority provably within the parent's).
- **Trust-boundary crossing records** (`TRUST_BOUNDARY_CROSSED`), including the privacy-preserving per-domain correlation profile.
- **Execution-continuity bootstrap** at token exchange (the bootstrap form of `EXECUTION_STARTED`).
- **Authenticated lineage checkpoints** and **full-history validation** for collusion-resistant assurance.
- **High-risk assurance-requirement profiles**, **independent checkpoint signing**, and optional **external anchoring** (the TRACE transparency profile: registry anchors, CLL/MMR checkpoint chains, COSE/SCITT-style receipts).
- **Attestation binding** (RATS `attestation_ref`) and the **instance-binding assessment**; **Evidence Packets** for offline verification (carrying the producer-key authorization statements and capability mapping needed to verify without reaching Lock).
- **AIMS/WIMSE identity and lifecycle features** — the WIMSE Agent Identifier profile, credential-aware `tokens[]` metadata, `workload_authentication`, `CREDENTIAL_PROVISIONED`, confirmation-vs-authorization (`USER_CONFIRMATION_RECORDED` / `APPROVAL_GRANTED`), and security-signal/remediation causal pairs (`SECURITY_SIGNAL_RECEIVED` / `REMEDIATION_APPLIED`).
- Where applicable, **Lock-as-PEP self-emission** for its own endpoints, once the self-reference/recursion and producer-key-vs-settlement-key hygiene constraints are resolved.

This phase enables end-to-end provenance across agents and trust domains, with explicit residual trust assumptions and independently verifiable assurance for highly confidential or regulated operations.

## Compatibility principle (all phases)

Every phase preserves backward compatibility with previously accepted records. The common foundation is the immutable producer assertion, the separation of producer-signed evidence from Lock-derived assessments, and the ability to explain exactly what was verified, what was not, and what evidence may be missing. Advanced features are additive profiles over the same signed-record model; they never alter, re-sign, or rewrite an assertion already accepted.

## References

- `Lock-Server-TRACE-MVP-Design.md` — Phase 1 (the MVP) in full: required scope, deferred features, and the single/bulk ingestion API.
- `design.md` — the full TRACE design that Phases 2–4 draw from (settlement, completeness, delegation, trust boundaries, anchoring, Alignment with TRACE v0.2).
- `cedarling-trace-design.md`, `auth-server-trace-design.md`, `fido-trace-design.md` — per-producer phased adoption, consistent with these phases.
- `jans-trace-core-mvp-design.md` — the deterministic signing/receipt-hash library underpinning Phase 1.
