# TRACE Phased Implementation Plan

TRACE is implemented incrementally. Each phase builds on the same signed-record model, so an MVP delivers useful evidence without requiring every assurance feature at launch. The phase boundaries below are reconciled with the current scope of `Lock-Server-TRACE-MVP-Design.md` (Phase 1 = the MVP) and `design.md` (the full design). **Those documents are authoritative**; this plan is a roadmap, so each item below names a capability and points at the design for its detail rather than restating field-level mechanics.

Each phase preserves backward compatibility with previously accepted records. Advanced features strengthen the evidence and its assurance level; they never change or rewrite the original signed assertions.

## Phases at a glance

| Phase | Theme | The question it answers |
|---|---|---|
| **1 — MVP Evidence Collection** | Collect attributable, tamper-evident evidence | *Who signed this, did the bytes survive unchanged, and which records belong together?* |
| **2 — Settlement and Ledger Integrity** | Lock stands behind the evidence | *Has Lock independently validated this record, not merely received it?* |
| **3 — Completeness and Context** | Put evidence in context and show what's missing | *Is the expected evidence complete, resolved to capabilities, and enriched with its token/operation context?* |
| **4 — Full Assurance** | End-to-end, offline, cross-domain assurance | *Can a third party verify this across agents and trust domains without trusting the operator?* |

## Phase 1 — MVP Evidence Collection

**Delivers attributable, tamper-evident evidence that can be correlated across producers, with ingestion-time integrity findings visible.** This is the full scope of `Lock-Server-TRACE-MVP-Design.md`.

- **Signed record ingestion** — single-record (`POST /api/v1/audit/trace`) and **bulk** (`POST /api/v1/audit/trace/bulk`, one producer per batch, per-record accept/reject); bulk is in the MVP because a high-throughput producer such as Cedarling emits thousands of decisions per second.
- **Administrative producer-key registration** — keys provisioned out of band (config or an admin-scoped API), scoped by `authorized_event_kinds`, never registered implicitly from a record; admission runs and persists the key-state checks (see `Lock-Server-TRACE-MVP-Design.md` §12).
- **Lock-derived evidence-domain isolation** — `evidence_domain_id` from the authenticated client, never the record body.
- **Signature, identity, and schema validation** — Ed25519 over RFC 8785 (JCS), `kid`-selected key, and the `signature_valid`/`identity_sound` admission gates.
- **Immutable preservation of producer assertions** — the signed `assertion` is byte-immutable; all Lock-derived data lives outside it.
- **Producer-chain sequencing** — `producer_chain_id`/`sequence_number`/`prev_record_hash`, one or more chains per producer instance, with `first_observed` genesis acceptable.
- **A Lock receipt hash chain** — the per-domain ingestion ledger (`receipt_sequence`/`received_at` at millisecond precision/`prev_receipt_hash`), assigned atomically with each accepted record.
- **Ingestion-time integrity flagging** — coverage-gap, chain-link-failure, equivocation, and late-arrival, each surfaced rather than silently dropped or resolved.
- **Correlation** by `(evidence_domain_id, execution_authority, trace_execution_id)`, required at ingestion (no unattributed-evidence/backfill path in the MVP).
- **Signed capability facts and effect state** — `AUTHORIZATION_DECISION` signs a `decision` and `CAPABILITY_INVOKED` an `invocation` (`{action, resource_type, outcome}`, singular by default, batch form optional); `RUNTIME_EFFECT` carries the required `effect_status` discriminator with the confirmed-effect invariant (a `confirmed` effect must bind a `result_digest` — a bytes-only check). The `capability_id` label is Lock-derived and its resolution/index are deferred (see `design.md`: Capability Resolution).
- **Retrieval by record and execution** — capability, workload, session, transaction, and token retrieval are deferred.
- **Structured errors and idempotent replay.**

> The **receipt hash chain** is Phase 1; the **signed receipt checkpoint** over it (the externally-anchorable commitment) is Phase 2 — the ledger exists before the commitment over it does.

## Phase 2 — Settlement and Ledger Integrity

**Lets Lock distinguish a *submitted claim* from *evidence it has independently validated and settled*.** It adds the Lock-attested assessment layer over the Phase 1 ledger. (Equivocation, coverage-gap, and late-arrival reporting are Phase 1, not here.)

- **Lock-signed settlement** — the per-record `submitted` → `settled` lifecycle over the settlement checks, first pass synchronous and re-settlement asynchronous as later evidence arrives (see `design.md`: Settlement; the checks split into bytes-only **Class-1** and state-dependent **Class-2**).
- **Signed receipt checkpoints** over the receipt ledger, using a Lock-owned ledger-signing key.
- **Key rotation and revocation handling** beyond basic validity — `kid`-based rotation-overlap selection and the TRACE v0.2 §3.2.3 revocation rule, with historical results immune to later revocation.
- **Trust-tier assignment** and the per-dimension verification vector (Lock-assigned, never producer-declared).

## Phase 3 — Completeness and Context

**Connects decisions to invocations and effects, and makes absent evidence explicit rather than assumed.**

- **Evidence-expectation profiles** and **execution completeness** (including the AIMS profile), surfacing gaps as `expected_evidence_missing`.
- **Capability resolution** — resolving `capability_id` from the signed `(action, resource_type)` + policy-store mapping, plus the capability index/retrieval.
- **Token enrichment** and **decision-time token-validation evidence**, and token-exchange/transaction-token lineage.
- **Operation-binding commitments** (`request_digest`/`tool_call_digest`/`result_digest`, and proof-of-possession binding).
- **Evidence-origin classification** (`evidence_origin`/`measurement_point`/`recorder`, and `effect_attestation` grading of who observed an effect) and the richer retrieval dimensions.
- **Disconnected candidate-record handling** and late-arrival correlation, including `CORRELATION_ASSERTED` backfill of previously-unattributed evidence.

## Phase 4 — Full Assurance

**Enables end-to-end provenance across agents and trust domains, with explicit residual trust assumptions and independently verifiable assurance for highly confidential or regulated operations.**

- **Delegation non-expansion validation** (child authority provably within the parent's).
- **Trust-boundary crossing records** (`TRUST_BOUNDARY_CROSSED`), including the privacy-preserving per-domain correlation profile.
- **Execution-continuity bootstrap** at token exchange.
- **Authenticated lineage checkpoints** and **full-history validation** for collusion-resistant assurance.
- **High-risk assurance-requirement profiles**, **independent checkpoint signing**, and optional **external anchoring** — the TRACE transparency profile, whose standards-track concrete form is CLL-over-MMR checkpoints registered to a SCITT Transparency Service (see `design.md`: External Anchoring and Transparency).
- **Attestation binding** (RATS) and the **instance-binding assessment**; **Evidence Packets** for offline verification (carrying the producer-key authorization statements and capability mapping needed to verify without reaching Lock).
- **AIMS/WIMSE identity and lifecycle features** — the WIMSE Agent Identifier profile, credential-aware `tokens[]` metadata, `workload_authentication`, `CREDENTIAL_PROVISIONED`, confirmation-vs-authorization, and security-signal/remediation pairs.
- Where applicable, **Lock-as-PEP self-emission** for its own endpoints, once the self-reference and producer-key-vs-settlement-key hygiene constraints are resolved.

## Compatibility principle (all phases)

Every phase preserves backward compatibility with previously accepted records. The common foundation is the immutable producer assertion, the separation of producer-signed evidence from Lock-derived assessments, and the ability to explain exactly what was verified, what was not, and what evidence may be missing. Advanced features are additive profiles over the same signed-record model; they never alter, re-sign, or rewrite an assertion already accepted.

## References

- `Lock-Server-TRACE-MVP-Design.md` — Phase 1 (the MVP) in full: required scope, deferred features, and the single/bulk ingestion API.
- `design.md` — the full TRACE design Phases 2–4 draw from: settlement, completeness, delegation, trust boundaries, anchoring, and the alignment sections (TRACE v0.2, Canonical Payload Binding, the CAN/WHO/WHAT/AUDIT composition model).
- `cedarling-trace-design.md`, `auth-server-trace-design.md`, `fido-trace-design.md` — per-producer phased adoption, consistent with these phases.
- `jans-trace-core-mvp-design.md` — the deterministic signing/receipt-hash library underpinning Phase 1.
