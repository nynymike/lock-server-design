# Lock Server TRACE — MVP Design

## 1. Purpose

This document defines the smallest useful implementation of TRACE evidence support in Janssen Lock Server. It is an implementation profile of the full TRACE design, not a replacement for it.

The MVP answers four practical questions about a governed agent action:

1. What capability was authorized?
2. What enforcement point attempted or performed the invocation?
3. What did each evidence producer sign?
4. Which records belong to the same governed execution?

The MVP provides attributable, tamper-evident records and basic correlation. It does **not** claim that an execution's evidence is complete, that a producer reported every event, or that a recorded action caused a claimed real-world effect.

## 2. MVP outcome

At the end of Phase 1, Lock Server can:

- accept a signed TRACE record from an authenticated producer;
- derive the record's evidence-domain partition from the submitting OAuth client;
- verify the producer identity, key, signature, and required schema;
- preserve the producer-signed assertion without modification;
- detect replay, record-ID conflict, producer-chain coverage gaps, chain-link failures, equivocation, and late arrival, flagging each rather than silently dropping or rejecting it;
- assign a Lock receipt sequence and append the record to Lock's receipt chain;
- correlate records by governed execution, capability, producer, and token reference; and
- retrieve either one record or the direct records for one execution.

This is sufficient to demonstrate the core evidence path:

`authorization decision → capability invocation → optional runtime effect`

The authorization decision and capability invocation should come from different control points. Cedarling records what was authorized. The PEP, agent gateway, or tool gateway that mediates the action records `CAPABILITY_INVOKED`. An agent's own statement that it invoked a capability is not equivalent to enforcement-point evidence.

## 3. Scope

### Required in the MVP

- OAuth-protected single-record ingestion.
- Per-evidence-domain producer-key registration through an administrative path (configuration or an admin API under a separate scope), never implicitly from a submitted record.
- Ed25519 signatures selected by signed `kid`.
- RFC 8785 JSON Canonicalization Scheme (JCS).
- Immutable storage of accepted producer assertions.
- Lock-derived verification and ingestion metadata.
- Execution correlation using `(evidence_domain_id, execution_authority, trace_execution_id)`.
- Record identity using `(evidence_domain_id, producer_id, record_id)`.
- Producer-local sequence and predecessor-hash checking.
- A Lock receipt hash chain.
- Multiple token references per record, identified by issuer plus `jti`, or by fingerprint when `jti` is absent.
- Retrieval by record and execution.
- Coverage-gap, chain-link-failure, equivocation, and late-arrival flagging.
- Structured errors and idempotent replay.

### Explicitly deferred

The MVP does not implement:

- settlement assessments or Lock-signed settlement receipts;
- execution completeness or assurance profiles, including the AIMS evidence-completeness profile;
- lineage checkpoints or claims of complete producer history;
- delegation non-expansion analysis;
- authorization-transition reconstruction;
- user-intent and approval records, including `USER_CONFIRMATION_RECORDED` and the `APPROVAL_GRANTED` authorization-grant binding (confirmation-vs-authorization distinction);
- operation-binding commitments, including proof-of-possession binding (`pop_binding` — WPT/HTTP-Message-Signature proof binding);
- token-claim enrichment or current-state resolution, and token-exchange / transaction-token lineage (including the forwarded-access-token anti-pattern finding);
- RATS-based attestation assessment or trust tiers;
- cross-domain correlation or import;
- privacy-preserving trust-boundary profiles;
- signed receipt checkpoints or external transparency anchoring;
- Evidence Packet export;
- bulk ingestion; or
- graph traversal beyond direct execution membership.

The MVP also defers the AIMS/WIMSE identity and lifecycle features the full design specifies:

- the WIMSE Agent Identifier profile (requiring `workload_id` to be a WIMSE URI) — the MVP accepts any stable `workload_id`, and defers `credential_type`/`audience`/`expiration`/`cnf_key_thumbprint`/`credential_id` on `tokens[]` (the MVP records only issuer/type/jti/fingerprint) and the `workload_authentication` record of how the workload authenticated (transport vs. application, mtls/wpt/http_message_signature);
- credential-provisioning evidence (`CREDENTIAL_PROVISIONED`) and its posture/assessment references; and
- security-signal and remediation evidence (`SECURITY_SIGNAL_RECEIVED` / `REMEDIATION_APPLIED`, the SSF/CAEP/RISC signal-and-remediation causal pair).

## 4. Security and responsibility boundaries

TRACE involves several parties with different responsibilities:

- A **policy decision point (PDP)**, such as Cedarling, decides whether a governed capability is allowed and produces an `AUTHORIZATION_DECISION` record.
- An **enforcement point**, such as a PEP, agent gateway, or tool gateway, mediates the action and produces a `CAPABILITY_INVOKED` record.
- An **evidence producer** signs the record it creates. A PDP or enforcement point is therefore a producer for its own records.
- A **submitting client** sends a signed record to Lock. It is usually the producer, but an approved forwarder may submit on a producer's behalf.
- **Lock Server** verifies, stores, correlates, and returns evidence. Lock does not decide whether the governed capability should run.

There are three independent security checks. They must not be confused:

| Check | Question answered | Mechanism |
|---|---|---|
| Capability authorization | May the agent exercise this action on this resource? | Cedarling or another PDP; the result is evidence recorded by TRACE. |
| TRACE API access control | May this client submit or read evidence through Lock's API? | OAuth access token, TRACE API scope, and Lock endpoint policy. |
| Record verification | Who signed this record, and have the signed fields changed? | Producer key lookup and Ed25519 signature verification. |

Lock performs the second and third checks. The first happened at the PDP and is what an `AUTHORIZATION_DECISION` record describes. 

### 4.1 Evidence-domain isolation

One Lock deployment may collect evidence for several organizations, environments, or other administrative partitions. Records from those partitions must not collide or become visible to one another. `evidence_domain_id` is the opaque Lock-local identifier for that isolation boundary.

Lock determines the domain from the authenticated submitting client and that client's configured domain binding. The producer does not choose the domain by placing a value in the record. Otherwise, a producer could claim another domain's identifier and attempt to write into its namespace.

Lock MUST NOT derive `evidence_domain_id` from the submitted assertion. If the body contains that field, Lock must either reject the request or ignore the field and flag the attempt; it must never use the submitted value for routing or storage.

Within Lock, the derived domain scopes producer-key lookup, record identity, execution correlation, indexes, and retrieval. A producer key registered in one evidence domain grants no authority in another. A producer serving several domains must have an explicit registration in each one.

A single-domain deployment may configure one implicit domain. It should still retain the internal partition so a later move to multiple domains does not change record identities or weaken isolation.

### 4.2 Submitting client and record producer

Before doing record-dependent work, Lock MUST validate that the OAuth client may use the TRACE ingestion endpoint—for example, by checking the access token and `trace.write` scope. This is ordinary API access control for Lock as an OAuth resource server. It is not a decision about whether the agent may exercise the capability described in the record.

After the API caller is accepted, Lock verifies the signed `producer` and `kid` against a producer key registered in the derived evidence domain. This establishes record authorship independently of the transport credential.

Normally the submitting OAuth client and signed producer represent the same component. They may differ only when Lock configuration explicitly allows the client to forward records for that producer. A forwarding client cannot replace the producer signature or select a different evidence domain in the record body.

## 5. Minimal architecture

The MVP has five logical components:

| Component | Responsibility |
|---|---|
| TRACE API | Validate API access, derive `evidence_domain_id`, and parse requests. It does not decide whether the governed capability is allowed. |
| Verification service | Validate schema, resolve `(evidence_domain_id, producer_id, kid)`, canonicalize, and verify the signature. |
| Producer key registry | Store trusted Ed25519 public keys and validity/revocation metadata per evidence domain. |
| Correlation service | Validate producer-chain position and create direct execution, capability, producer, and token indexes. |
| TRACE store | Atomically persist the assertion, verification metadata, ingestion metadata, and receipt-chain entry. |

Processing order is fixed:

1. Validate the OAuth client and its permission to use the TRACE endpoint.
2. Derive `evidence_domain_id`.
3. Validate the JSON structure and limits.
4. Resolve the signed producer and `kid` within that domain.
5. Verify the Ed25519 signature over the JCS form of every assertion field except `signature`.
6. Compute `content_digest` over the JCS form of the complete assertion, including `signature`.
7. Apply idempotency, conflict, chain-gap, and equivocation checks.
8. Atomically store the record and append its Lock receipt entry.
9. Return the acceptance result.

Unverified records MUST NOT enter the normal TRACE store or any retrieval index. An implementation may place them in a separately access-controlled quarantine.

## 6. Producer key registration

Each key is identified by:

`(evidence_domain_id, producer_id, kid)`

The minimum key record is:

```json
{
  "producer_id": "cedarling-fleet-1",
  "kid": "key-2026-01",
  "public_key_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "..."
  },
  "authorized_event_kinds": ["AUTHORIZATION_DECISION"],
  "valid_from": "2026-01-01T00:00:00Z",
  "valid_until": null,
  "revoked_at": null
}
```

`producer_id` is the **stable logical producer** (`cedarling-fleet-1`), not a `name/semver` string — software version is separate signed metadata (see §7.1), so a software upgrade does not force a new producer identity, key, or chain. `authorized_event_kinds` scopes which event kinds this key may sign; a record whose `event_kind` is outside the key's authorized set is **rejected**, exactly like an unknown key (the full design elaborates this as the `producer_authorized_for_claim` check). The full design additionally scopes a key by `authorized_measurement_points` (which collection points the key may claim); the MVP defers that finer scoping and enforces only `authorized_event_kinds`.

**Keys are provisioned administratively, never implicitly.** Lock registers producer keys through configuration or an **administrative API protected by a separate scope** (e.g. `trace.producers.manage`, distinct from `trace.write`). Lock MUST NOT accept a public key merely because it accompanied the first record — that would make the signature self-authenticating. Possession of a signing key must not let the holder define its own producer identity or claim scope; those come only from the administrative registration. Authorization rests on that independently provisioned registration, **not** on the mere fact that a key was found at the lookup index `(evidence_domain_id, producer_id, kid)` — the index locates a candidate key; the administrative registration is what grants authority. (The full design expresses this registration as a portable, administratively-signed **Producer-Key Authorization Statement** that binds the key by thumbprint for offline verification; the MVP relies on Lock's live registry and defers that artifact along with Evidence Packets — see §3.)

The assertion MUST carry `kid` inside the signed scope. Lock selects the key by `kid`; it must not guess the key from the record timestamp. Key rotation may leave old keys available for historical verification. Revoking a key later must not rewrite a verification result recorded before the revocation.

## 7. Minimal TRACE assertion

The following is the MVP wire shape. Fields shown as `null` may be omitted unless an event-kind rule requires them.

```json
{
  "producer": "cedarling-fleet-1/1.0.0",
  "kid": "cedarling-fleet-1-2026-01",
  "record_id": "9f3e9e2a-6b0e-4b2c-9f6e-3a2f7b0c9d41",
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
    "event": {
      "outcome": "ALLOW",
      "decisions": [
        {
          "action": "Acme::Action::\"Pay\"",
          "resource_type": "Acme::Payment",
          "outcome": "ALLOW"
        }
      ],
      "tokens": [
        {
          "issuer": "https://accounts.example.org",
          "token_type": "access_token",
          "jti": "9c9f2e77-9a3e-4b62-9a2a-2f6e6e2a9f3e"
        }
      ]
    },
    "policy": {
      "policy_store_id": "https://example.org/policy-stores/payments",
      "policy_store_version": "1.2.3",
      "policy_language": "cedar",
      "policy_language_version": "4.4.0",
      "bundle_hash": "sha256:..."
    },
    "runtime": {
      "pdp_id": "cedarling-001"
    }
  },
  "producer_chain": {
    "producer_id": "cedarling-fleet-1/1.0.0",
    "producer_instance_id": "cedarling-001",
    "producer_chain_id": "chain-01JABC9Z0K",
    "sequence_number": 4821,
    "prev_record_hash": "sha256:..."
  },
  "parent_record_ids": [
    {
      "producer_id": "jans-auth-server/1.0.0",
      "record_id": "R-token-issued-001",
      "relationship_type": "issued_token"
    }
  ],
  "signature": "base64url(...)"
}
```

### 7.1 Required common fields

| Field | MVP rule |
|---|---|
| `producer` | Required. **Stable logical producer identifier** (e.g. `cedarling-fleet-1`), not a `name/semver` string. Must equal `producer_chain.producer_id` byte-for-byte. Software version/build/runtime, when carried, travel as separate signed metadata (e.g. `producer_version`), never folded into `producer_id`. |
| `kid` | Required and signed. Selects the registered verification key. |
| `record_id` | Required and producer-generated UUID or ULID. |
| `trace.eat_profile` | Required and fixed to the supported TRACE profile version. |
| `trace.event_kind` | Required and limited to the MVP event catalog below. |
| `trace.signed_at` | Required NumericDate. Producer time; not treated as receipt time. |
| `trace.trace_execution_id` | Required for the MVP. |
| `trace.execution_authority` | Required. Scopes the execution ID. Distinct from `subject.workload_id` (see below): the authority scopes the execution identifier, the workload is the subject participating in it. |
| `trace.subject.workload_id` | **Event-specific.** Required for `AUTHORIZATION_DECISION` and `CAPABILITY_INVOKED` (these records identify the workload requesting or exercising the capability); not required for event kinds where no workload is known or relevant. |
| `trace.subject.workload_instance_id` | Optional. Some deployments cannot reliably identify a particular process, pod, or runtime instance. |
| `trace.event` | Required; shape depends on `event_kind`. |
| `producer_chain` | Required. Identifies the producer-local chain and position. |
| `parent_record_ids` | Optional array of typed causal references. Empty array is valid. |
| `signature` | Required base64url Ed25519 signature. |

Requiring the execution ID at ingestion deliberately avoids correlation-backfill behavior in Phase 1.

The **execution initiator** — whichever component creates the governed unit of work — creates the `(execution_authority, trace_execution_id)` pair and propagates it to the PDP, enforcement point, and effect observer. There is no single Jans component that always plays this role: it may be an agent runtime or workflow engine, an agent/API/tool gateway, a PEP receiving the first governed request, an application host embedding Cedarling, or a scheduler starting an autonomous job. `trace_execution_id` and `execution_authority` always travel together. Cedarling and Lock do **not** generate these identifiers — Cedarling consumes the normalized context and Lock correlates the resulting evidence. Lock does not mint the identifier or authorize the execution; it uses the signed pair to correlate evidence. If a producer cannot obtain that context, it cannot submit the record under the MVP profile and must wait for the later correlation-backfill feature.

Note that `execution_authority` and `workload_id` are **different concepts**: the authority scopes the execution identifier, while the workload is the subject participating in the execution. They are identical in the §7 example above, but they do not have to be.

#### Canonical propagation wire profile

To keep nominally-conforming producers correlatable, the MVP fixes one canonical mapping for the base correlation fields. A host, sidecar, PEP, or gateway translates the applicable carrier into the producer's (and Cedarling's) input model.

| TRACE field | HTTP header | OTel baggage key | Token claim |
|---|---|---|---|
| `trace_execution_id` | `Audit-Trace-ID` | `audit.trace_id` | `https://jans.io/trace/execution_id` |
| `execution_authority` | `Audit-Execution-Authority` | `audit.execution_authority` | `https://jans.io/trace/execution_authority` |
| `workload_id` | `Audit-Workload-ID` | `audit.workload_id` | `https://jans.io/trace/workload_id` |
| `workload_instance_id` | `Audit-Workload-Instance-ID` | `audit.workload_instance_id` | `https://jans.io/trace/workload_instance_id` |

Rules accompanying the mapping:

- `trace_execution_id` and `execution_authority` MUST travel together.
- Cedarling receives normalized values through its authorization API. It does not parse headers, tokens, or OTel baggage.
- The host, sidecar, PEP, or gateway translates the applicable carrier into Cedarling's input model.
- Unsigned headers and baggage are correlation hints, not authoritative claims.
- A trusted ingress component SHOULD validate or replace externally-supplied values rather than forwarding them blindly.
- Signed token claims provide stronger binding, but their issuer and signature MUST still be validated.
- When several carriers disagree, precedence is validated token claim, then trusted ingress/host input, then unsigned header, then OTel baggage; the conflict MUST be recorded rather than silently resolved.

Every `parent_record_ids` reference is resolved inside the same Lock-derived `evidence_domain_id`. Cross-domain causal edges are not supported by the MVP.

### 7.2 MVP event catalog

The MVP recognizes only the three event kinds needed for the capability-evidence path:

| Event kind | Producer | Minimum event data |
|---|---|---|
| `AUTHORIZATION_DECISION` | Cedarling or another PDP | `outcome`; non-empty `decisions[]` (each `{action, resource_type, outcome}` — the signed Cedar action and resource type, no resource id); complete `trace.policy` block; and `trace.runtime.pdp_id`. |
| `CAPABILITY_INVOKED` | PEP, agent gateway, or tool gateway | non-empty `invocations[]` (each `{action, resource_type}`), `enforcement_point_id`, and invocation `outcome`. |
| `RUNTIME_EFFECT` | Target system or trusted observer | effect `outcome` (the only hard requirement, matching the full design); normally a `produced_effect` parent edge to the originating invocation, and SHOULD carry a result/target identifier or `result_digest` when available so the effect is useful evidence rather than a bare outcome. |

`AUTHORIZATION_DECISION` and `CAPABILITY_INVOKED` are required for the primary capability-governance flow. `RUNTIME_EFFECT` is optional. Authentication, FIDO, lifecycle, correlation-backfill, delegation, intent, approval, and transition events are deferred to later phases.

These requirements intentionally match the corresponding event-kind schemas in the full design. The MVP narrows the catalog; it does not define weaker versions of the retained event kinds. **Producers sign the capability *facts*, not the governance label.** An `AUTHORIZATION_DECISION` signs `decisions[]` (`{action, resource_type, outcome}`) and a `CAPABILITY_INVOKED` signs `invocations[]` (`{action, resource_type}`) — the concrete Cedar action and resource *type* (never a resource id). The governance label **`capability_id` is Lock-derived in the full design** (resolved from the signed `(action, resource_type)` plus `policy_store_id`/`policy_store_version` against a versioned mapping in the policy store, stored as `capability_resolution` outside the signed assertion — see `.kiro/specs/lock-server-trace-records/design.md`: Capability Resolution). The **MVP defers that resolution and the capability index** (see §13): the MVP records the signed facts so they are forward-compatible, but does not require Lock to resolve `capability_id` or to serve capability-keyed retrieval. `RUNTIME_EFFECT` carries neither `decisions[]` nor `invocations[]`; its causal link to the invocation is expressed by `parent_record_ids`.

Lock MUST validate the schema for the declared `event_kind` and reject fields that contradict that kind. Lock records evidence; it does not infer that an authorization caused an invocation merely because their timestamps are close. Producers express causal relationships with `parent_record_ids`.

#### What each record establishes (and does not)

Each record kind establishes a **narrow, specific claim** and nothing stronger. This boundary is normative: Lock, and any system consuming Lock's MVP evidence, MUST NOT promote a record into a claim it does not make — a lower-level piece of evidence is never silently elevated into proof of authorization, correctness, or occurrence it does not carry.

| Record | Establishes | Does **not** establish |
|---|---|---|
| `AUTHORIZATION_DECISION` | The PDP signed that it returned this decision under the referenced policy. | That the action occurred or was appropriate. |
| `CAPABILITY_INVOKED` | The enforcement point asserts it mediated the invocation. | That the target produced the claimed effect. |
| `RUNTIME_EFFECT` | The observer asserts that it observed the effect. | That the effect was authorized. |
| Lock receipt | Lock accepted these bytes at this position in its receipt chain. | That the producer's assertion is true or complete. |

This mirrors the full design's per-record-kind claim boundaries, narrowed to the MVP's three event kinds and its receipt chain. It is the MVP expression of the §14 rule that a valid signature is not equated with truth, completeness, independent observation, or successful enforcement.

### 7.3 Token references

`tokens[]` is an array because one decision or action may use several tokens. Each entry MUST contain:

- canonical `issuer` URI;
- `token_type`; and
- either `jti` or `fingerprint`.

The external token identity is `(evidence_domain_id, issuer, jti)`, never bare `jti`. When no `jti` exists, Lock uses `(evidence_domain_id, issuer, fingerprint)`. Raw bearer tokens MUST NOT be stored.

Token claims, decision-time validation details, revocation freshness, token lineage, and later Lock enrichment are deferred. Their omission must be reported as “not captured,” never as “valid.”

## 8. Producer chain

Each producer instance maintains one or more chains. Lock does not impose a global order across producers, and does not impose a single chain per instance.

- `producer_chain_id` identifies one chain instance.
- A producer instance MAY own **more than one chain concurrently**: the model is `producer_id → producer_instance_id → one or more producer_chain_id values`. Each record belongs to exactly one chain and each chain stays strictly linear, but a busy instance (e.g. an embedded Cedarling handling many concurrent `authorize_*` calls) MAY allocate chains by worker, partition, thread, or execution lane so concurrent writers do not contend on one serialized sequence allocator. TRACE does not claim a total order within an instance; cross-chain ordering comes from causal links and `trace_execution_id`.
- `sequence_number` increases by one within one chain.
- `prev_record_hash` is the prior position's `content_digest`.
- The genesis record uses `sequence_number: 1` and the configured all-zero predecessor sentinel.

**Genesis authentication.** The signing **key** is always administratively registered first (§6); genesis authentication is a separate question about the *chain*. For deployments needing stronger lineage assurance, a chain genesis is **pre-registered** with Lock (`pre_registered_genesis`). Otherwise an already-registered key MAY open a new chain simply by submitting its first signed record, which Lock anchors at first sight as `first_observed_genesis`. A first-observed chain establishes tamper-evident history from the moment Lock sees it, but cannot establish complete producer history before that point.

**Restart does not automatically mean a new chain.** A producer that has **durably retained** its `producer_chain_id`, last `sequence_number`, and previous record hash SHOULD **continue its existing chain** across a restart. A new chain is necessary only when that state is unavailable, when a new independently-sequenced writer is created, or when the producer deliberately rotates to another chain. Where a new chain is unavoidable, its genesis SHOULD reference the previous chain head where known (the full design specifies the signed `chain_link`; the MVP records the reference and defers full link validation).

**Cedarling deployment patterns.** The MVP recognizes that the producer's longevity and key custody vary by deployment: **embedded/server Cedarling** — the host supplies the key and durable chain state; **sidecar Cedarling** — the sidecar owns the key and one or more chain writers; **ephemeral pod** — uses a fleet or workload-provisioned key and opens a `first_observed_genesis` chain for that pod/writer; **WASM Cedarling** — preferably returns the assertion to a trusted host for signing, since a browser-held key provides weaker producer assurance and is classified accordingly. The rule throughout: keys identify trusted producers, chains identify independently-sequenced record streams, and versions describe software — they are not the same identifier.

Records may arrive out of order. A missing predecessor does not cause rejection: Lock accepts the record with `coverage_gap_flag: true` and clears that derived condition when the missing position arrives and links correctly. A present but nonmatching predecessor is a different case: Lock accepts the record with `chain_link_failure_flag: true`, a genuine chain-link break rather than a pending gap. Unlike a coverage gap, this flag is **not** self-clearing — the conflicting predecessor is already present, so later arrival cannot resolve it — and it remains visible as an integrity finding.

If independently valid records with different `record_id` values claim the same `(evidence_domain_id, producer_id, producer_instance_id, producer_chain_id, sequence_number)`, Lock stores and flags both records as equivocation. It never silently selects a winner. This differs from reuse of the same `record_id`, which is a content conflict and cannot create two records under one primary key.

Producer order, Lock receipt order, and causal relationships are separate:

- producer order says what one producer signed in sequence;
- receipt order says when Lock accepted records; and
- `parent_record_ids` says which causal relationship a producer asserted.

None is a global event clock.

## 9. Lock receipt chain

For every accepted record, Lock atomically assigns:

- `receipt_sequence`: monotonically increasing within the evidence domain's Lock receipt chain;
- `received_at`: Lock's receipt timestamp; and
- `prev_receipt_hash`: hash of the preceding receipt entry.

The receipt-entry hash MUST bind at least:

`evidence_domain_id`, `receipt_sequence`, `received_at`, `producer_id`, `record_id`, `content_digest`, and `prev_receipt_hash`.

This chain makes local insertion, deletion, and rewriting detectable during verification. Without signed checkpoints or an independent external anchor, it does not prove integrity against a Lock operator able to rewrite the entire chain. The API and documentation must not overstate that guarantee.

## 10. Stored envelope

Lock stores three clearly separated parts:

```json
{
  "assertion": {
    "...": "the complete producer-signed record, unchanged"
  },
  "content_digest": "sha256:...",
  "verification": {
    "signature_valid": true,
    "key_id": "cedarling-fleet-1-2026-01",
    "key_thumbprint": "sha256:...",
    "verified_at": "2026-06-11T00:41:02Z",
    "algorithm": "Ed25519",
    "key_authorized": true
  },
  "ingestion": {
    "receipt_sequence": 108422,
    "received_at": "2026-06-11T00:41:02Z",
    "prev_receipt_hash": "sha256:...",
    "coverage_gap_flag": false,
    "chain_link_failure_flag": false,
    "equivocation_flag": false,
    "late_flag": false
  }
}
```

`assertion` is byte-immutable after acceptance. Lock MUST NOT insert resolved claims, status, trust, corrections, or receipt data into it. Future assessments must be stored beside the assertion as new Lock-authored artifacts.

`content_digest` is a top-level Lock-computed envelope value used for replay and conflict detection; it is not a signature-verification result. The producer signature is verified over JCS canonical bytes of every assertion field except `signature`. `content_digest` is SHA-256 over JCS canonical bytes of the full assertion including `signature`. These scopes are intentionally different.

The `verification` block records the admission decision Lock made at `verified_at`, so it is not reconstructed later from mutable registry state: `signature_valid`, the verifying `key_id` and its `key_thumbprint` (the thumbprint pins the exact key independently of the non-unique `kid` selector), and `key_authorized` — a single boolean capturing that the key existed, was within its validity window, was not revoked, was registered for this `producer_id`, and was authorized for the record's `event_kind` (the admission checks of §6). A later re-scoping, revocation, or validity change of the key never rewrites these recorded results for an already-stored record. The MVP keeps `key_authorized` as one boolean; the full design decomposes it into separately-recorded `key_resolved`/`key_temporally_valid`/`key_not_revoked`/`key_authorized_for_producer`/`producer_authorized_for_claim` results and binds them to a signed Producer-Key Authorization Statement for offline verification — both deferred here. (The MVP records no `trust_tier`; trust tiers are deferred per §3.)

## 11. API

### 11.1 Submit one record

```http
POST /api/v1/audit/trace
Authorization: Bearer <access-token>
Content-Type: application/json
```

Required scope:

`https://jans.io/oauth/lock/trace.write`

Success response:

```json
{
  "accepted": true,
  "producer_id": "cedarling-fleet-1/1.0.0",
  "record_id": "9f3e9e2a-6b0e-4b2c-9f6e-3a2f7b0c9d41",
  "content_digest": "sha256:...",
  "receipt_sequence": 108422,
  "idempotent_replay": false,
  "coverage_gap_flag": false,
  "chain_link_failure_flag": false,
  "equivocation_flag": false,
  "late_flag": false
}
```

Return `202 Accepted` only after verification and atomic persistence succeed. Use `400` for malformed or invalid signed content, `401`/`403` for OAuth failures, `409` for reuse of the same record identity with different content, and `500` when durable storage cannot complete. A deployment may use `503` instead when it deliberately exposes a retryable service-unavailable condition, but the OpenAPI contract must choose one behavior consistently.

### 11.2 Retrieve one record

```http
GET /api/v1/audit/trace/records/{record_id}?producer_id={producer_id}
```

Required scope:

`https://jans.io/oauth/lock/trace.readonly`

`producer_id` SHOULD be supplied. If omitted, Lock may return the record only when the bare ID resolves to exactly one producer within the authenticated evidence domain; otherwise it returns an ambiguity error.

### 11.3 Retrieve one execution

```http
GET /api/v1/audit/trace/executions/{trace_execution_id}?execution_authority={execution_authority}
```

The MVP response contains the execution identity and its directly associated records, ordered by Lock receipt sequence. It does not claim global event order, traverse child executions, or compute completeness.

`execution_authority` SHOULD be supplied. If omitted, Lock may return the execution only when the bare ID resolves uniquely within the authenticated evidence domain.

## 12. Idempotency and errors

| Condition | Required behavior |
|---|---|
| Same composite record identity and same `content_digest` | Return the original acceptance result with `idempotent_replay: true`; do not append a second receipt. |
| Same composite record identity and different `content_digest` | Return `409`; never overwrite the first record. |
| Unknown producer or `kid` | Reject or quarantine; do not index. |
| `event_kind` outside the key's `authorized_event_kinds` | Reject; a key authorized for one event kind cannot sign another. |
| Invalid signature | Reject or quarantine; do not index. |
| `producer` differs from `producer_chain.producer_id` | Reject. |
| Missing required execution scope | Reject in the MVP. |
| Missing predecessor | Accept and flag a coverage gap. |
| Present predecessor with wrong digest | Accept and flag the chain-link failure; never report the chain as intact. |
| Same chain position, different `record_id`, and valid signatures | Store and flag both records as equivocation; never select one silently. |
| Record received substantially later than `signed_at` | Accept and set `late_flag: true` under a configurable lateness policy; lateness alone is not a rejection reason. |
| Storage or receipt append failure | Fail the request with the storage-failure status chosen in §11.1 (`500`, or `503` if the deployment exposes a retryable condition); no partial record, receipt entry, or index entry may remain visible. |

## 13. Minimum storage keys and indexes

The implementation needs only these keys and indexes:

- primary record key: `(evidence_domain_id, producer_id, record_id)`;
- execution index: `(evidence_domain_id, execution_authority, trace_execution_id)`;
- producer-chain position: `(evidence_domain_id, producer_id, producer_instance_id, producer_chain_id, sequence_number)`;
- token index: `(evidence_domain_id, issuer, jti-or-fingerprint)`; and
- receipt-chain position: `(evidence_domain_id, receipt_sequence)`.

Capability resolution and the capability index (`(evidence_domain_id, capability_id)`), and session, workload, transaction, assessment, checkpoint, and graph-traversal indexes, may be added in later phases. The signed `(action, resource_type)` facts the MVP records make the capability index addable later without re-emitting records.

## 14. Security requirements

- Enforce TLS and OAuth on every TRACE endpoint.
- Derive the evidence domain before any key lookup or content-based routing.
- Apply maximum request size, nesting depth, string length, and array length before expensive cryptographic processing.
- Use constant-time cryptographic implementations and approved Ed25519 libraries.
- Never log raw bearer tokens or sensitive token claims.
- Preserve the original assertion and the exact verifying `kid` for historical verification.
- Treat producer timestamps as claims. Use `received_at` for Lock receipt order.
- Authorize reads within the same evidence domain as writes; never perform cross-domain fallback searches.
- Do not equate a valid signature with truth, completeness, independent observation, or successful enforcement.
- Do not label the MVP evidence as `settled`, `complete`, or externally anchored.

## 15. MVP acceptance criteria

The MVP is complete when all of the following tests pass:

1. A valid record from a client permitted to use the TRACE API is verified, stored unchanged, indexed, and assigned exactly one receipt sequence.
2. An invalid signature, unknown key, or mismatched producer identity never appears in normal retrieval.
3. Replaying identical content returns the original receipt without creating another entry.
4. Reusing a record identity with changed content cannot overwrite the accepted record.
5. Two producers may use the same `record_id` without collision because `producer_id` scopes identity.
6. Two issuers may use the same `jti` without collision because `issuer` scopes token identity.
7. A record may reference multiple tokens and all references are indexed.
8. A producer-chain gap is visible, and out-of-order arrival can resolve the gap without rewriting assertions.
9. Equivocation at one producer-chain position is visible and no conflicting record is silently preferred.
10. Execution retrieval never crosses an evidence domain and never silently guesses among ambiguous authorities.
11. The authorization decision and enforcement-point invocation can be retrieved under the same execution.
12. A failed atomic write leaves neither a visible record, receipt entry, nor index entry.
13. A record lookup never returns a matching identifier from another evidence domain.
14. An unscoped record or execution lookup with several in-domain matches returns an ambiguity error rather than selecting one.
15. A record signed by a key not authorized for its `producer_id`, or whose `event_kind` is outside the key's `authorized_event_kinds`, is rejected and never appears in normal retrieval — exactly as an unknown key is.
16. A stored record's recorded admission decision (`signature_valid`, `key_thumbprint`, `key_authorized`) is fixed at `verified_at`: later re-scoping, revocation, or validity-window changes to the key never rewrite it for an already-stored record.

## 16. Later phases

Phase 2 can add signed settlement assessments, receipt checkpoints, richer retrieval, token claims captured at decision time, and operation-binding commitments (including proof-of-possession binding). Phase 3 can add completeness and assurance profiles, delegation and authorization-state analysis, lineage validation, external transparency, and Evidence Packets for offline verification.

The AIMS/WIMSE identity and lifecycle features layer onto these phases without altering the MVP's accepted assertions: the WIMSE Agent Identifier profile and the AIMS-recognized credential metadata on `tokens[]`; the `workload_authentication` record of how a workload authenticated; credential-provisioning/posture evidence (`CREDENTIAL_PROVISIONED`); user-confirmation-vs-authorization evidence (`USER_CONFIRMATION_RECORDED` with the `APPROVAL_GRANTED` authorization-grant binding); token-exchange/transaction-token lineage and the forwarded-access-token anti-pattern finding; security-signal and remediation evidence (`SECURITY_SIGNAL_RECEIVED` / `REMEDIATION_APPLIED`); and the AIMS evidence-completeness profile that checks an execution against the AIMS audit minimum. Each is an additive `event_kind`, optional field, or Lock-derived assessment.

All later features should remain additive: they may assess, correlate, checkpoint, or package an accepted assertion, but must never rewrite it.
