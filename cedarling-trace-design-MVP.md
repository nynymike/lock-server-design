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
| Stable logical `producer_id` | **Yes** | MVP §7.1 requires a stable logical `producer` byte-equal to `producer_chain.producer_id`, not a `name/semver` string. |
| Separate `producer_version` | **No** | Optional in Lock MVP §7.1 and only a build label; the format is versioned by `eat_profile`. Cedarling leaves it out in the MVP; it can be added later without a new profile. |
| Administratively-provisioned producer key, scoped `authorized_event_kinds: ["AUTHORIZATION_DECISION"]` | **Yes** | MVP §6 requires admin provisioning and `authorized_event_kinds`; an out-of-scope `event_kind` is rejected. |
| Producer chain (`producer_chain_id`, `sequence_number`, `prev_record_hash`) | **Yes** | MVP §8 requires producer-local sequencing and predecessor hashing. Cedarling runs one chain per instance and opens a new `first_observed_genesis` chain at every start (§4). |
| Provide `(execution_authority, trace_execution_id)` on every record | **Yes — and required at ingestion** | MVP §7.1 makes both required; there is **no unattributed-evidence path** (see §3 below). |
| signed `decision` (`{action, resource_type, outcome}`; Cedarling has no atomic multi-pair evaluation, so it never writes `decisions[]`), `trace.policy` (`policy_store_id`/`version`/`language`/`language_version`/`bundle_hash`), `trace.runtime.pdp_id` | **Yes** | MVP §7.2 requires these for `AUTHORIZATION_DECISION`. Cedarling signs the `(action, resource_type)` **facts**, not a `capability_id`. |
| Compute / sign a `capability_id` | **No** | `capability_id` is Lock-derived (full design); the MVP defers resolution and the capability index entirely. Cedarling signs only `(action, resource_type)`. |
| `tokens[]` with `issuer` / `token_type` / `jti`-or-`fingerprint` | **Yes (minimal)** | MVP §7.3 records only these; raw bearer tokens never stored. |
| `validation_at_decision` / `revocation_freshness` / `token_claims[]` | **No** | MVP defers token-claim enrichment and decision-time validation detail. |
| Operation-binding digests (`request_digest` / `tool_call_digest` / `input_digest`) | **No** | MVP defers operation-binding commitments. |
| Record a `trust_tier` / consume settlement | **No** | MVP defers trust tiers and settlement; Lock records neither in the MVP. |
| Producer-Key Authorization Statement for offline verification | **No** | MVP defers Evidence Packets; Lock relies on its live registry. |
| Chain-genesis pre-registration / lineage checkpoints | **No** | Cedarling uses only `first_observed` genesis, so Lock must run with `chainRegistrationMode: FIRST_OBSERVED` (Lock MVP §8). Lock must also list the Cedarling `producer` in the client's `allowedProducerIds`, or in `defaultAllowedProducerIds` for a client without its own binding (Lock MVP §4.2): with Lock's defaults every Cedarling record is refused. `history_complete` and lineage assurance are deferred. |
| `authorized_measurement_points` scoping | **No** | MVP enforces only `authorized_event_kinds`. |

Everything in the "Yes" rows Cedarling already has the inputs for (it holds the decision, the policy-store metadata, the `pdp_id`, and the normalized correlation context); the MVP additions are signing, the producer chain, and reading the required correlation pair.

## 3. The one hard MVP constraint: `trace_execution_id` is required at ingestion

This is the single most important MVP difference from the full Cedarling design, and it changes Cedarling's missing-context behavior.

The **full design** allows Cedarling to emit an `AUTHORIZATION_DECISION` **without** `trace_execution_id` when no execution context is available: Lock stores it as **unattributed evidence** and correlates it later (a `CORRELATION_ASSERTED` backfill or operator action), and Cedarling returns a `trace_record_status: "not_emitted_missing_context"` diagnostic.

The **MVP does not support this.** `Lock-Server-TRACE-MVP-Design.md` §7.1 makes `trace.trace_execution_id` and `trace.execution_authority` **required**, and states plainly that requiring the execution ID at ingestion "deliberately avoids correlation-backfill behavior in Phase 1" — "If a producer cannot obtain that context, it cannot submit the record under the MVP profile and must wait for the later correlation-backfill feature." There is no unattributed-evidence path and no `CORRELATION_ASSERTED` in the MVP.

Consequently, for the MVP, Cedarling's rule is:

- Cedarling reads the normalized `(execution_authority, trace_execution_id)` pair supplied through its authorization API — the optional `options.trace` member of every authorization request (`AuthorizeOptions { trace: TraceContext }` with `execution_id`, `execution_authority`, `workload_id`, and optional `workload_instance_id`; one context per batch call) (the host/sidecar/PEP/gateway having translated whichever carrier was in use — `Audit-Trace-ID`/`Audit-Execution-Authority` headers, the `https://jans.io/trace/execution_id` / `https://jans.io/trace/execution_authority` token claims, or `audit.trace_id` / `audit.execution_authority` baggage — into Cedarling's input model). Cedarling itself does not parse headers, token wire formats, or baggage.
- **When the pair is present**, Cedarling stamps it into the `AUTHORIZATION_DECISION` and emits normally.
- **When the pair is absent**, Cedarling **does not emit an MVP TRACE record** (it still returns its normal `AuthorizeResult` and may emit its operational decision log; the decision is never blocked). It still surfaces the `trace_record_status: "not_emitted_missing_context"` diagnostic and increments the operational metric, exactly as in the full design (an empty required context member counts as absent) — but in the MVP the record is simply **not submitted**, rather than submitted as unattributed evidence. Cedarling still never fabricates a `trace_execution_id`.
- A deployment that requires TRACE evidence for governed operations therefore ensures the execution initiator supplies the correlation pair before the decision; the host/PEP MAY treat a `not_emitted_missing_context` diagnostic as a governance failure. Cedarling remains the PDP and never turns evidence collection into an authorization decision.

**Where the diagnostic appears.** `AuthorizeResult` is unchanged. With TRACE enabled, each decision-log entry carries `trace_record_status`, and the metrics count each value as `trace.<status>`. Besides `emitted` (the record was queued for sending) and `not_emitted_missing_context`, the MVP uses: `not_emitted_over_limit` (a value exceeds a Lock limit; Cedarling never truncates a signed value), `not_emitted_invalid_field` (a value Lock would reject, such as a JWT issuer that is not `https`), `not_emitted_queue_full` (the queue to the emitter is full, e.g. while Lock is down), `not_emitted_stopped`, and `not_emitted_no_endpoint`. In every case the record is never signed, so the producer chain has no hole, and the decision is unchanged. Whether Lock accepted an emitted record shows in the metrics (`trace.accepted`, `trace.rejected`, `trace.dropped`) and the emitter log, not per decision.

The two values always travel together (the MVP requires it), and `execution_authority` scopes the execution id — it is distinct from `subject.workload_id` (the workload participating in the execution), even when they happen to be the same SPIFFE URI in a given example.

## 4. The MVP `AUTHORIZATION_DECISION` record

Cedarling assembles, canonicalizes (RFC 8785 JCS), and signs (Ed25519) a record matching the MVP wire shape (`Lock-Server-TRACE-MVP-Design.md` §7). The MVP-required content Cedarling populates:

- **Envelope identity** — `producer` as a **stable logical identifier** (e.g. `cedarling-fleet-1`, from `CEDARLING_TRACE_PRODUCER_ID`, defaulting to `CEDARLING_APPLICATION_NAME`), byte-equal to `producer_chain.producer_id`; the build version is never folded into `producer_id`, and the MVP does not emit `producer_version` (§2). `kid` selects the registered verification key: `CEDARLING_TRACE_SIGNING_KID` when set, otherwise the key thumbprint (`sha256:` + hex, RFC 7638), which Cedarling logs at startup for registering the key. `record_id` is the existing per-call UUIDv7 `request_id`, so the record and the decision-log entry share it.
- **Producer chain** — `producer_instance_id` is the Cedarling `pdp_id`; `producer_chain_id` / `sequence_number` / `prev_record_hash` maintained per the MVP §8 rules, advanced atomically with signing so no two records claim one sequence position (equivocation). In the MVP an instance runs **one** chain and keeps no durable chain state: every start opens a new `producer_chain_id` with a `first_observed_genesis` record. Cedarling sends the genesis alone and signs the rest of the chain only after Lock accepts it, so Lock (which rejects a non-genesis record of an unregistered chain, Lock MVP §8) never sees records it must refuse. If Lock loses or refuses the chain, Cedarling opens a new one. Several chains per instance (by worker/lane) remain permitted by MVP §8 and are deferred: one chain signs about 25,000 records/s, far more than Lock accepts from it, so a second chain would not raise throughput (`trace-mvp-post-mvp.md` §4.1).
- **Correlation** — required `trace_execution_id` + `execution_authority` (see §3); `subject.workload_id` required for `AUTHORIZATION_DECISION` (the workload the decision was made for), `workload_instance_id` optional.
- **Event** — a singular `decision` `{action, resource_type, outcome}` (`ALLOW`/`DENY` from the Cedar decision; a `DENY` still lists the attempted `{action, resource_type}`); and `tokens[]` carrying only `issuer` / `token_type` / `jti`-or-`fingerprint` for `authorize_multi_issuer` (omitted for `authorize_unsigned`). Cedarling always writes the singular `decision`; `authorize_*_batch` yields one record per item. In `tokens[]`: `issuer` is the JWT `iss`, or `urn:jans:cedarling:custom-issuer:<issuer>` for a token from a custom (non-JWT) processor; `token_type` is the token's Cedar entity type from the policy store (e.g. `Jans::Access_Token`); `fingerprint`, used when there is no `jti`, is `sha256:` + hex of the token exactly as received. A decision with more than 32 tokens, or with a value over a Lock limit, yields no record (§3). Cedarling signs no `capability_id` — the label is Lock-derived in the full design and deferred in the MVP.
- **Policy** — `trace.policy` with `policy_store_id` / `policy_store_version` (from loaded policy-store metadata), `policy_language: "cedar"`, `policy_language_version` (the Cedar language version Cedarling reports at startup), and `bundle_hash`: `sha256:` + hex SHA-256 of the raw bytes of the `.cjar` archive Cedarling loaded, exactly as received, computed at every (re)load. This is the same value Lock computes for the archives it serves (Lock MVP §10). TRACE therefore needs a `.cjar` policy store source (local file, URL, Lock, or URI); with a directory or YAML store and TRACE enabled, Cedarling refuses to start.
- **Runtime** — `trace.runtime.pdp_id` (the same `pdp_id`).
- **Signature** — `base64url(Ed25519 over RFC 8785 JCS bytes of all fields except signature)`, computed by `jans-trace-core` (the same library Lock can verify with), using the instance's administratively-registered producer key (an unencrypted PKCS#8 PEM Ed25519 key) (scoped `authorized_event_kinds: ["AUTHORIZATION_DECISION"]`), distinct from any Lock key.

Cedarling produces **only** the decision half of the GovOps pairing. It never produces `CAPABILITY_INVOKED` — the MVP (like the full design) requires the enforcement-point record to be signed by the enforcement point's own key; the enforcement point links back via `parent_record_ids` (`relationship_type: "authorized"`). Timestamps Cedarling supplies (`signed_at`) are producer claims; Lock uses `received_at` for ordering.

## 5. What Cedarling does NOT need for the MVP

Deferred to later phases and specified in `cedarling-trace-design.md`:

- **No token-claim enrichment.** No `validation_at_decision` (signature/contents/status checks), no `revocation_freshness`, no `token_claims[]`/`claims_at_decision`. The MVP's `tokens[]` carries only issuer/type/jti/fingerprint; the omission of decision-time validation detail is reported as "not captured," never as "valid" (MVP §7.3).
- **No operation-binding digests.** No `request_digest` / `tool_call_digest` / `input_digest`; cross-record binding to a downstream `CAPABILITY_INVOKED` is a later-phase, high-assurance addition.
- **No trust tier, no settlement awareness.** The MVP records no `trust_tier` and issues no settlement receipts; Cedarling neither supplies nor consumes these. (The acceptance response may carry MVP flags like `coverage_gap_flag`, but not a settlement status.)
- **No Producer-Key Authorization Statement handling / Evidence Packet participation.** The MVP relies on Lock's live registry; the portable signed authorization artifact and offline packet verification are deferred.
- **No unattributed-evidence / `CORRELATION_ASSERTED` emission.** Per §3, a record without the correlation pair is simply not submitted under the MVP.
- **No lineage-checkpoint / `history_complete` assurance.** `first_observed` genesis is acceptable in the MVP; genesis pre-registration for full lineage assurance is deferred.
- **No durable chain state, no lanes, no `chain_link`.** One chain per instance, new at every start; the new genesis does not reference the previous chain head. Whether a chain must survive a restart is an open question (`trace-mvp-post-mvp.md` Q1).
- **No WASM producer.** TRACE requires a native build. Whether TRACE must work in WASM, and who would sign there, is an open question (`trace-mvp-post-mvp.md` Q2).
- **No `producer_version`** (§2).

The items Cedarling deferred while implementing the MVP, with the condition for returning to each, are listed in `trace-mvp-post-mvp.md`.

## 6. Configuration (MVP subset)

Reusing the `CEDARLING_*` convention, the MVP needs the record-producing switch and its key/transport settings; the enrichment and binding toggles are deferred:

| Property | MVP role | Default |
|---|---|---|
| `CEDARLING_TRACE` | `enabled`/`disabled` — master switch for `AUTHORIZATION_DECISION` TRACE emission. Requires `CEDARLING_LOCK`, a `.cjar` policy store, a signing key, and a native build; Cedarling refuses to start otherwise. | `disabled` |
| `CEDARLING_TRACE_PRODUCER_ID` | The stable logical `producer`/`producer_id` (not `name/semver`); same character rule as Lock MVP §7.1. | `CEDARLING_APPLICATION_NAME` |
| `CEDARLING_TRACE_SIGNING_KEY` | Path to the Ed25519 producer signing key, an unencrypted PKCS#8 PEM file (e.g. a mounted secret). Preferred. | — |
| `CEDARLING_TRACE_SIGNING_KEY_PEM` | The same key as PEM text, for hosts that pass secrets only as values. Used only when `CEDARLING_TRACE_SIGNING_KEY` is unset; the configuration then holds a secret. | — |
| `CEDARLING_TRACE_SIGNING_KID` | The `kid` the key is registered under in Lock. | key thumbprint |
| `CEDARLING_TRACE_ENDPOINT` | Lock TRACE bulk endpoint: `discovered` (Lock's `trace_bulk_endpoint`, Lock MVP §11.7) or a URL. Must be `https`, or `http` only to loopback, because requests carry the Lock token; otherwise Cedarling logs a `WARN` and sends nothing (`not_emitted_no_endpoint`). | `discovered` |
| `CEDARLING_TRACE_TRANSPORT` | `rest` or `grpc` (Lock MVP §11.6), independent of the transport of the other Lock channels. | `rest` |
| `CEDARLING_TRACE_BULK_MAX_RECORDS` / `CEDARLING_TRACE_BULK_MAX_BYTES` | Maximum records and bytes per bulk request; keep them at most Lock's `maxBulkRecords` / `maxBulkRequestBytes`. | `100` / 4 MiB (Lock defaults) |

`CEDARLING_TRACE_CHAIN_GENESIS` and `CEDARLING_TRACE_EMISSION` are not implemented in the MVP: each would have exactly one value (`first_observed`, `all`), so a switch would change nothing. They are added when a second value is (see Scaling below and `trace-mvp-post-mvp.md`).

Deferred (full design only): `CEDARLING_TRACE_INCLUDE_CLAIMS` (token-claim enrichment) and `CEDARLING_TRACE_OPERATION_BINDING` (operation-binding digests). TRACE transport reuses the existing `CEDARLING_LOCK_*` machinery (SSA→DCR, buffered channel, retry) but requests the TRACE ingestion scope **`https://jans.io/oauth/lock/trace.write`** at DCR — the Lock TRACE endpoints require `trace.write`, not `log.write` (Lock MVP §11).

**Sending (MVP behavior).** The authorization call only puts the record facts into a bounded queue (`CEDARLING_LOCK_LOG_CHANNEL_CAPACITY`) and returns; a full queue gives `not_emitted_queue_full`. One background emitter takes whatever the queue holds (up to the bulk limits), signs it, and sends it at once; the next batch accumulates while a request is in flight, so `CEDARLING_LOCK_LOG_INTERVAL` does not apply. Retries resend the same bytes. A request that may succeed later (no answer, `5xx`, `429`, `408`) is retried up to `CEDARLING_LOCK_LOG_MAX_RETRIES` times, with a wait of 10 s doubling to 5 min; a per-record `5xx` error in a `207` is retried for that record. Any other refusal is final and logged with the setting to change. On `401` Cedarling renews its token once through `client_credentials` and resends; `403` is final. While Lock keeps refusing, the emitter backs off the same way between requests instead of sending one per decision. Records given up after the retries are lost, and Lock shows the hole as a coverage gap: the MVP has no durable outbox.

**Scaling (bulk ingestion; selective emission deferred).** Cedarling can make thousands of decisions per second. In the MVP the scale lever is bulk ingestion alone; the selective-emission filter is defined but deferred. (1) **Bulk ingestion** — records ship to Lock's `POST /api/v1/audit/trace/bulk` endpoint (now in the MVP — see `Lock-Server-TRACE-MVP-Design.md` §11.2), one producer per batch, per-record accept/reject, through a bounded queue and natural batches (see Sending above), rather than one request per decision. (2) **Selective emission (deferred past the MVP)** — the MVP has no `CEDARLING_TRACE_EMISSION` property and always emits `all`: Cedarling emits one record for **every** `authorize_*` decision (matching Acceptance criterion 2), and bulk ingestion is the only scale lever the MVP relies on. The `configured_capabilities` value — emitting only for an operator-configured `(action, resource_type)` allow-list — is defined for the full design but **not wired in the MVP**: the full design must still specify *where* that allow-list is configured before a pod can honor it, so the MVP leaves it out rather than ship an undefined filter. The honesty rule that governs it once it exists: a decision not emitted is absent evidence (**"not captured," never "no decision occurred"**), and Lock's completeness profiles (deferred in the MVP but defined in the full design) mark an expected-but-absent capability as `expected_evidence_missing`, so a deployment that must prove a capability was evidenced configures it into the emit set. Emission policy never changes the decision returned to the caller.

## 7. Acceptance criteria (MVP)

Cedarling's MVP TRACE support is complete when:

1. With `CEDARLING_TRACE` disabled (default), Cedarling behaves exactly as today — operational decision logs only, no signed TRACE records.
2. With it enabled and a correlation pair present, **every** `authorize_*` decision yields one signed `AUTHORIZATION_DECISION` — the MVP applies no capability filter (`CEDARLING_TRACE_EMISSION` is not implemented: emission is always `all`; the `configured_capabilities` filter is deferred, see §6 Scaling) — carrying a stable logical `producer`, `kid`, `record_id`, `(trace_execution_id, execution_authority)`, `subject.workload_id`, a signed `decision` (`{action, resource_type, outcome}`, no `capability_id`), a complete `trace.policy`, `trace.runtime.pdp_id`, and a valid Ed25519/JCS signature; the record advances the producer chain by exactly one sequence position.
3. With it enabled but **no** correlation pair present, Cedarling emits **no** MVP TRACE record, returns its normal `AuthorizeResult` (the decision is never blocked), surfaces `trace_record_status: "not_emitted_missing_context"` in its decision log and metrics (§3), and never fabricates a `trace_execution_id`.
4. A record signed by a key whose `authorized_event_kinds` does not include `AUTHORIZATION_DECISION` is rejected by Lock at admission (`unknown_producer_key`, MVP §12), confirming Cedarling's key scope; Cedarling logs the refusal and counts it in `trace.rejected`.
5. Cedarling populates no `validation_at_decision`, `token_claims[]`, operation-binding digests, or `trust_tier`; their absence is honestly "not captured," never asserted as present.
6. The signed `assertion` is byte-stable (RFC 8785 JCS) such that Lock re-derives identical bytes and verifies the signature; a one-bit change to any signed field fails verification.

## 8. Phased path (how this grows into the full design)

The MVP is Phase 1 of the full `cedarling-trace-design.md` adoption path:

- **MVP (this document) = full design Phase 1.** Signed, sequenced `AUTHORIZATION_DECISION` records with the producer key, chain, required correlation, and policy context — minus token enrichment, operation binding, and trust/settlement awareness (which the MVP Lock Server does not evaluate anyway).
- **Post-MVP — full token and policy context** (full design Phase 2). `validation_at_decision` with `revocation_freshness`, and `token_claims[]`.
- **Post-MVP — high assurance** (full design Phase 3). Chain-genesis pre-registration, operation-binding digests (provable pairing with downstream `CAPABILITY_INVOKED`), and lineage checkpoints.

Each step is additive over the same signed-record foundation and leaves the Cedar evaluation hot path unchanged. The concrete items the MVP implementation deferred are listed in `trace-mvp-post-mvp.md`.

## References

- `Lock-Server-TRACE-MVP-Design.md` — the Lock Server MVP profile: three-kind event catalog, required `(execution_authority, trace_execution_id)` at ingestion (no unattributed-evidence path), `AUTHORIZATION_DECISION` minimum event data, administrative key provisioning with `authorized_event_kinds`, producer-chain rules, and the deferred token-enrichment / operation-binding / settlement / trust-tier features.
- `cedarling-trace-design.md` — the full Cedarling producer design this MVP subsets (token enrichment, operation binding, Producer-Key Authorization Statement, phased adoption).
- `design.md` — the full TRACE design (record model, `AUTHORIZATION_DECISION` schema, correlation and propagation model).
- `research/cedarling_docs.txt` — Cedarling authorization interfaces, decision logs, Lock integration, bootstrap properties, JWT validation.
