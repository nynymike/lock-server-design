# Cedarling TRACE Support — MVP Design

## 1. Purpose

This document specifies what the **Cedarling** (the embeddable, Rust-based Cedar PDP) must do to support the **Lock Server TRACE MVP** defined in `Lock-Server-TRACE-MVP-Design.md`. It is the MVP-scoped companion to `cedarling-trace-design.md` (the full design).

Unlike the Auth Server and FIDO Server MVP companions — whose producers are deferred out of the MVP entirely — **Cedarling is a first-class MVP record producer.** It signs the `AUTHORIZATION_DECISION` record, which is one of the MVP's three event kinds (`AUTHORIZATION_DECISION`, `CAPABILITY_INVOKED`, `RUNTIME_EFFECT`). Cedarling is, in fact, the primary source of the MVP's first evidence kind: the Lock MVP's demonstrated flow is `authorization decision → capability invocation → optional runtime effect`, and Cedarling produces that first step.

So this is a substantive MVP document: it defines the minimal `AUTHORIZATION_DECISION` producer Cedarling must become for the MVP, and marks precisely which of the full design's producer responsibilities are deferred.

Scope of this document:

- The MVP subset of Cedarling's `AUTHORIZATION_DECISION` producer responsibilities (signing, producer chain, required correlation, policy context).
- The one hard MVP constraint that differs from the full design: `trace_execution_id` is **required at ingestion** — there is no unattributed-evidence path in the MVP.
- What is explicitly deferred to the post-MVP phases (token enrichment, operation binding, trust tiers, the authorization-statement artifact).

Non-goals: this document does not redefine the TRACE record model or the Lock ingestion pipeline (owned by `design.md`, profiled by `Lock-Server-TRACE-MVP-Design.md`), and it does not restate the full Cedarling producer design (owned by `cedarling-trace-design.md`).

## 2. MVP scope check: what the MVP needs from Cedarling

The Lock Server MVP (`Lock-Server-TRACE-MVP-Design.md` §3, §7) bears on Cedarling as follows:

| Full-design Cedarling responsibility | In the MVP? | Notes |
|---|---|---|
| Sign `AUTHORIZATION_DECISION` records | **Yes** | Cedarling is the MVP's PDP producer; this is its core MVP role. |
| Stable logical `producer_id` + separate `producer_version` | **Yes** | MVP §7.1 requires a stable logical `producer` byte-equal to `producer_chain.producer_id`, not a `name/semver` string. |
| Administratively-provisioned producer key, scoped `authorized_event_kinds: ["AUTHORIZATION_DECISION"]` | **Yes** | MVP §6 requires admin provisioning and `authorized_event_kinds`; an out-of-scope `event_kind` is rejected. |
| Producer chain (`producer_chain_id`, `sequence_number`, `prev_record_hash`) | **Yes** | MVP §8 requires producer-local sequencing and predecessor hashing; multiple chains per instance permitted. |
| Provide `(execution_authority, trace_execution_id)` on every record | **Yes — and required at ingestion** | MVP §7.1 makes both required; there is **no unattributed-evidence path** (see §3 below). |
| signed `decisions[]` (`{action, resource_type, outcome}`), `trace.policy` (`policy_store_id`/`version`/`language`/`language_version`/`bundle_hash`), `trace.runtime.pdp_id` | **Yes** | MVP §7.2 requires these for `AUTHORIZATION_DECISION`. Cedarling signs the `(action, resource_type)` **facts**, not a `capability_id`. |
| Compute / sign a `capability_id` | **No** | `capability_id` is Lock-derived (full design); the MVP defers resolution and the capability index entirely. Cedarling signs only `(action, resource_type)`. |
| `tokens[]` with `issuer` / `token_type` / `jti`-or-`fingerprint` | **Yes (minimal)** | MVP §7.3 records only these; raw bearer tokens never stored. |
| `validation_at_decision` / `revocation_freshness` / `token_claims[]` | **No** | MVP defers token-claim enrichment and decision-time validation detail. |
| Operation-binding digests (`request_digest` / `tool_call_digest` / `input_digest`) | **No** | MVP defers operation-binding commitments. |
| Record a `trust_tier` / consume settlement | **No** | MVP defers trust tiers and settlement; Lock records neither in the MVP. |
| Producer-Key Authorization Statement for offline verification | **No** | MVP defers Evidence Packets; Lock relies on its live registry. |
| Chain-genesis pre-registration / lineage checkpoints | **Optional / deferred** | MVP accepts `first_observed` genesis; `history_complete` and lineage assurance are deferred. |
| `authorized_measurement_points` scoping | **No** | MVP enforces only `authorized_event_kinds`. |

Everything in the "Yes" rows Cedarling already has the inputs for (it holds the decision, the policy-store metadata, the `pdp_id`, and the normalized correlation context); the MVP additions are signing, the producer chain, and reading the required correlation pair.

## 3. The one hard MVP constraint: `trace_execution_id` is required at ingestion

This is the single most important MVP difference from the full Cedarling design, and it changes Cedarling's missing-context behavior.

The **full design** allows Cedarling to emit an `AUTHORIZATION_DECISION` **without** `trace_execution_id` when no execution context is available: Lock stores it as **unattributed evidence** and correlates it later (a `CORRELATION_ASSERTED` backfill or operator action), and Cedarling returns a `trace_record_status: "not_emitted_missing_context"` diagnostic.

The **MVP does not support this.** `Lock-Server-TRACE-MVP-Design.md` §7.1 makes `trace.trace_execution_id` and `trace.execution_authority` **required**, and states plainly that requiring the execution ID at ingestion "deliberately avoids correlation-backfill behavior in Phase 1" — "If a producer cannot obtain that context, it cannot submit the record under the MVP profile and must wait for the later correlation-backfill feature." There is no unattributed-evidence path and no `CORRELATION_ASSERTED` in the MVP.

Consequently, for the MVP, Cedarling's rule is:

- Cedarling reads the normalized `(execution_authority, trace_execution_id)` pair supplied through its authorization API (the host/sidecar/PEP/gateway having translated whichever carrier was in use — `Audit-Trace-ID`/`Audit-Execution-Authority` headers, the `https://jans.io/trace/execution_id` / `https://jans.io/trace/execution_authority` token claims, or `audit.trace_id` / `audit.execution_authority` baggage — into Cedarling's input model). Cedarling itself does not parse headers, token wire formats, or baggage.
- **When the pair is present**, Cedarling stamps it into the `AUTHORIZATION_DECISION` and emits normally.
- **When the pair is absent**, Cedarling **does not emit an MVP TRACE record** (it still returns its normal `AuthorizeResult` and may emit its operational decision log; the decision is never blocked). It still surfaces the `trace_record_status: "not_emitted_missing_context"` diagnostic and increments the operational metric, exactly as in the full design — but in the MVP the record is simply **not submitted**, rather than submitted as unattributed evidence. Cedarling still never fabricates a `trace_execution_id`.
- A deployment that requires TRACE evidence for governed operations therefore ensures the execution initiator supplies the correlation pair before the decision; the host/PEP MAY treat a `not_emitted_missing_context` diagnostic as a governance failure. Cedarling remains the PDP and never turns evidence collection into an authorization decision.

The two values always travel together (the MVP requires it), and `execution_authority` scopes the execution id — it is distinct from `subject.workload_id` (the workload participating in the execution), even when they happen to be the same SPIFFE URI in a given example.

## 4. The MVP `AUTHORIZATION_DECISION` record

Cedarling assembles, canonicalizes (RFC 8785 JCS), and signs (Ed25519) a record matching the MVP wire shape (`Lock-Server-TRACE-MVP-Design.md` §7). The MVP-required content Cedarling populates:

- **Envelope identity** — `producer` as a **stable logical identifier** (e.g. `cedarling-fleet-1`, from `CEDARLING_APPLICATION_NAME`), byte-equal to `producer_chain.producer_id`; the Cedarling build version travels as separate signed metadata (e.g. `producer_version`), never folded into `producer_id`. `kid` selects the registered verification key. `record_id` is a producer-generated UUID/ULID (Cedarling can reuse its existing per-call UUIDv7 `request_id`).
- **Producer chain** — `producer_instance_id` is the Cedarling `pdp_id`; `producer_chain_id` / `sequence_number` / `prev_record_hash` maintained per the MVP §8 rules, advanced atomically with signing so no two records claim one sequence position (equivocation). A busy instance MAY run more than one chain (by worker/lane) per MVP §8; each chain stays strictly linear. A restart that cannot resume durable chain state opens a new `producer_chain_id` (surfacing as an ordinary coverage gap), consistent with MVP §8.
- **Correlation** — required `trace_execution_id` + `execution_authority` (see §3); `subject.workload_id` required for `AUTHORIZATION_DECISION` (the workload the decision was made for), `workload_instance_id` optional.
- **Event** — `outcome` (`ALLOW`/`DENY` from the Cedar decision); non-empty `decisions[]` (each `{action, resource_type, outcome}` — the signed Cedar action and resource type, no resource id; a `DENY` still lists the attempted `{action, resource_type}`); and `tokens[]` carrying only `issuer` / `token_type` / `jti`-or-`fingerprint` for `authorize_multi_issuer` (omitted for `authorize_unsigned`). Cedarling signs no `capability_id` — the label is Lock-derived in the full design and deferred in the MVP.
- **Policy** — `trace.policy` with `policy_store_id` / `policy_store_version` (from loaded policy-store metadata), `policy_language: "cedar"`, `policy_language_version` (the Cedar language version Cedarling reports at startup), and `bundle_hash` (computed once per loaded store and cached).
- **Runtime** — `trace.runtime.pdp_id` (the same `pdp_id`).
- **Signature** — `base64url(Ed25519 over RFC 8785 JCS bytes of all fields except signature)`, using the instance's administratively-registered producer key (scoped `authorized_event_kinds: ["AUTHORIZATION_DECISION"]`), distinct from any Lock key.

Cedarling produces **only** the decision half of the GovOps pairing. It never produces `CAPABILITY_INVOKED` — the MVP (like the full design) requires the enforcement-point record to be signed by the enforcement point's own key; the enforcement point links back via `parent_record_ids` (`relationship_type: "authorized"`). Timestamps Cedarling supplies (`signed_at`) are producer claims; Lock uses `received_at` for ordering.

## 5. What Cedarling does NOT need for the MVP

Deferred to later phases and specified in `cedarling-trace-design.md`:

- **No token-claim enrichment.** No `validation_at_decision` (signature/contents/status checks), no `revocation_freshness`, no `token_claims[]`/`claims_at_decision`. The MVP's `tokens[]` carries only issuer/type/jti/fingerprint; the omission of decision-time validation detail is reported as "not captured," never as "valid" (MVP §7.3).
- **No operation-binding digests.** No `request_digest` / `tool_call_digest` / `input_digest`; cross-record binding to a downstream `CAPABILITY_INVOKED` is a later-phase, high-assurance addition.
- **No trust tier, no settlement awareness.** The MVP records no `trust_tier` and issues no settlement receipts; Cedarling neither supplies nor consumes these. (The acceptance response may carry MVP flags like `coverage_gap_flag`, but not a settlement status.)
- **No Producer-Key Authorization Statement handling / Evidence Packet participation.** The MVP relies on Lock's live registry; the portable signed authorization artifact and offline packet verification are deferred.
- **No unattributed-evidence / `CORRELATION_ASSERTED` emission.** Per §3, a record without the correlation pair is simply not submitted under the MVP.
- **No lineage-checkpoint / `history_complete` assurance.** `first_observed` genesis is acceptable in the MVP; genesis pre-registration for full lineage assurance is deferred.

## 6. Configuration (MVP subset)

Reusing the `CEDARLING_*` convention, the MVP needs the record-producing switch and its key/transport settings; the enrichment and binding toggles are deferred:

| Property | MVP role | Default |
|---|---|---|
| `CEDARLING_TRACE` | `enabled`/`disabled` — master switch for `AUTHORIZATION_DECISION` TRACE emission. | `disabled` |
| `CEDARLING_TRACE_PRODUCER_ID` | The stable logical `producer`/`producer_id` (not `name/semver`). | derived from app name |
| `CEDARLING_TRACE_SIGNING_KEY` | Reference to the Ed25519 producer signing key (handle; never inline). | — |
| `CEDARLING_TRACE_CHAIN_GENESIS` | `pre_registered`/`first_observed` — MVP accepts `first_observed`. | `first_observed` |
| `CEDARLING_TRACE_EMISSION` | `all` / `configured_capabilities` — which decisions become records (see Scaling below). | `configured_capabilities` |
| `CEDARLING_TRACE_ENDPOINT` | Lock TRACE ingestion endpoint; the **bulk** path `/api/v1/audit/trace/bulk` by default, or the discovered Lock audit endpoint. | discovered |

Deferred (full design only): `CEDARLING_TRACE_INCLUDE_CLAIMS` (token-claim enrichment) and `CEDARLING_TRACE_OPERATION_BINDING` (operation-binding digests). TRACE transport reuses the existing `CEDARLING_LOCK_*` machinery (SSA→DCR, `log.write` scope, buffered channel, retry).

**Scaling (bulk + selective emission).** Cedarling can make thousands of decisions per second, so the MVP relies on two levers, both available in the Lock Server MVP. (1) **Bulk ingestion** — records ship to Lock's `POST /api/v1/audit/trace/bulk` endpoint (now in the MVP — see `Lock-Server-TRACE-MVP-Design.md` §11.2), one producer per batch, per-record accept/reject, over the existing buffered/periodic channel, rather than one request per decision. (2) **Selective emission** — `CEDARLING_TRACE_EMISSION` defaults to `configured_capabilities`, emitting records only for the operator-configured `(action, resource_type)` capabilities that matter for governance, rather than signing every decision; `all` emits for every decision at higher cost. The honesty rule holds either way: a decision not emitted is absent evidence (**"not captured," never "no decision occurred"**), and Lock's completeness profiles (deferred in the MVP but defined in the full design) mark an expected-but-absent capability as `expected_evidence_missing`, so a deployment that must prove a capability was evidenced configures it into the emit set. Emission policy never changes the decision returned to the caller.

## 7. Acceptance criteria (MVP)

Cedarling's MVP TRACE support is complete when:

1. With `CEDARLING_TRACE` disabled (default), Cedarling behaves exactly as today — operational decision logs only, no signed TRACE records.
2. With it enabled and a correlation pair present, each `authorize_*` decision yields one signed `AUTHORIZATION_DECISION` carrying a stable logical `producer`, `kid`, `record_id`, `(trace_execution_id, execution_authority)`, `subject.workload_id`, non-empty signed `decisions[]` (`{action, resource_type, outcome}`, no `capability_id`), a complete `trace.policy`, `trace.runtime.pdp_id`, and a valid Ed25519/JCS signature; the record advances the producer chain by exactly one sequence position.
3. With it enabled but **no** correlation pair present, Cedarling emits **no** MVP TRACE record, returns its normal `AuthorizeResult` (the decision is never blocked), surfaces `trace_record_status: "not_emitted_missing_context"`, and never fabricates a `trace_execution_id`.
4. A record signed by a key whose `authorized_event_kinds` does not include `AUTHORIZATION_DECISION` is rejected by Lock at admission (MVP §12), confirming Cedarling's key scope.
5. Cedarling populates no `validation_at_decision`, `token_claims[]`, operation-binding digests, or `trust_tier`; their absence is honestly "not captured," never asserted as present.
6. The signed `assertion` is byte-stable (RFC 8785 JCS) such that Lock re-derives identical bytes and verifies the signature; a one-bit change to any signed field fails verification.

## 8. Phased path (how this grows into the full design)

The MVP is Phase 1 of the full `cedarling-trace-design.md` adoption path:

- **MVP (this document) = full design Phase 1.** Signed, sequenced `AUTHORIZATION_DECISION` records with the producer key, chain, required correlation, and policy context — minus token enrichment, operation binding, and trust/settlement awareness (which the MVP Lock Server does not evaluate anyway).
- **Post-MVP — full token and policy context** (full design Phase 2). `validation_at_decision` with `revocation_freshness`, and `token_claims[]`.
- **Post-MVP — high assurance** (full design Phase 3). Chain-genesis pre-registration, operation-binding digests (provable pairing with downstream `CAPABILITY_INVOKED`), and lineage checkpoints.

Each step is additive over the same signed-record foundation and leaves the Cedar evaluation hot path unchanged.

## References

- `Lock-Server-TRACE-MVP-Design.md` — the Lock Server MVP profile: three-kind event catalog, required `(execution_authority, trace_execution_id)` at ingestion (no unattributed-evidence path), `AUTHORIZATION_DECISION` minimum event data, administrative key provisioning with `authorized_event_kinds`, producer-chain rules, and the deferred token-enrichment / operation-binding / settlement / trust-tier features.
- `cedarling-trace-design.md` — the full Cedarling producer design this MVP subsets (token enrichment, operation binding, Producer-Key Authorization Statement, phased adoption).
- `design.md` — the full TRACE design (record model, `AUTHORIZATION_DECISION` schema, correlation and propagation model).
- `research/cedarling_docs.txt` — Cedarling authorization interfaces, decision logs, Lock integration, bootstrap properties, JWT validation.
