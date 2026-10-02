# Jans Auth Server TRACE Support — MVP Design

## 1. Purpose

This document specifies the **minimum** the Janssen Auth Server (the OpenID Provider) must do to support the **Lock Server TRACE MVP** defined in `Lock-Server-TRACE-MVP-Design.md`. It is the MVP-scoped companion to `auth-server-trace-design.md` (the full design) and parallels the Lock Server MVP's deliberately narrow profile.

The headline finding is a scoping one, and it is stated up front because it determines everything below:

> **In the Lock Server MVP, the Auth Server is not a TRACE *record producer*.** The MVP event catalog is exactly three kinds — `AUTHORIZATION_DECISION`, `CAPABILITY_INVOKED`, `RUNTIME_EFFECT` — and it explicitly defers authentication, lifecycle, and correlation-backfill events. The Auth Server's primary TRACE contributions in the full design — the `AUTHENTICATION_EVENT` record and the token-exchange bootstrap `EXECUTION_STARTED` — are **both outside the MVP catalog**. So the Auth Server signs **no TRACE records** in the MVP.

What the Auth Server *does* contribute to the MVP is **correlation origination**: the MVP requires every ingested record to carry a `(execution_authority, trace_execution_id)` pair, and that pair has to be minted by an execution initiator and *propagated* to the producers that do sign records (Cedarling and the enforcement point). The Auth Server, as the component that mints OAuth/OIDC tokens, is the natural place to **carry that correlation context in token claims** when an execution context is known at issuance time. That is a token-shaping change, not a TRACE-record change, and it is the Auth Server's one materially useful MVP role.

Scope of this document:

- Why the Auth Server produces no MVP TRACE records, stated against the MVP event catalog and correlation rules.
- The one MVP-relevant capability: carrying `(execution_authority, trace_execution_id)` in issued token claims so downstream producers can satisfy the MVP's required correlation fields.
- What is explicitly deferred to the post-MVP phases (and lives in the full `auth-server-trace-design.md`).

Non-goals: this document does not redefine the TRACE record model or the Lock ingestion pipeline (owned by `design.md` and profiled by `Lock-Server-TRACE-MVP-Design.md`), and it does not restate the full Auth Server producer design (owned by `auth-server-trace-design.md`).

## 2. MVP scope check: what the MVP needs from the Auth Server

The Lock Server MVP (`Lock-Server-TRACE-MVP-Design.md` §3, §7.2) fixes these boundaries that bear on the Auth Server:

- **Event catalog is three kinds only.** `AUTHORIZATION_DECISION` (Cedarling/PDP), `CAPABILITY_INVOKED` (PEP/gateway), `RUNTIME_EFFECT` (target/observer). "Authentication, FIDO, lifecycle, correlation-backfill, delegation, intent, approval, and transition events are deferred to later phases."
- **`trace_execution_id` is required at ingestion.** The MVP "deliberately avoids correlation-backfill behavior." A producer that cannot obtain the execution context cannot submit under the MVP profile. There is **no unattributed evidence** path in the MVP.
- **Cedarling and Lock do not mint the correlation identifiers.** The MVP's execution-initiator rule says `(execution_authority, trace_execution_id)` is created by whichever component begins the governed unit of work and is then propagated to the PDP, enforcement point, and effect observer.
- **Token-exchange / transaction-token lineage is deferred.** So is settlement, trust tiers, Evidence Packets, and the finer `authorized_measurement_points` scoping.

Mapping those against the Auth Server's full-design responsibilities:

| Full-design Auth Server responsibility | In the MVP? | Why |
|---|---|---|
| Sign `AUTHENTICATION_EVENT` records | **No** | `AUTHENTICATION_EVENT` is not in the MVP's three-kind catalog; authentication events are explicitly deferred. |
| Emit token-exchange bootstrap `EXECUTION_STARTED` | **No** | `EXECUTION_STARTED` (incl. the bootstrap form) is a lifecycle kind, outside the MVP catalog; token-exchange lineage is deferred. |
| Maintain a producer key, producer chain, genesis | **No** | Only needed to *sign records*; the Auth Server signs none in the MVP, so no producer key, chain, `producer_chain_id`, sequence, or genesis is required of it. |
| Act as **unattributed-evidence** source correlated later | **No** | The MVP has no unattributed/backfill path; authentication-before-execution correlation is a deferred feature. |
| **Carry `(execution_authority, trace_execution_id)` in issued token claims** | **Yes (optional, recommended)** | Supports the MVP's required correlation fields on the records that *are* produced (Cedarling, PEP). This is the Auth Server's only MVP-relevant role. |

So the MVP Auth Server work is small and additive, and a deployment can run the full Lock Server MVP with the Auth Server completely unchanged — provided the execution initiator and the propagation carriers (headers / OTel baggage / token claims) deliver `(execution_authority, trace_execution_id)` to the producers by some other means. The Auth Server's token-claim support simply makes the **signed-token carrier** of that correlation available, which is the strongest of the MVP's carriers.

## 3. The one MVP capability: correlation context in token claims

The MVP's canonical propagation wire profile (`Lock-Server-TRACE-MVP-Design.md` §7.1) fixes one mapping for the base correlation fields across HTTP headers, OTel baggage, and **token claims**:

| TRACE field | HTTP header | OTel baggage key | Token claim |
|---|---|---|---|
| `trace_execution_id` | `Audit-Trace-ID` | `audit.trace_id` | `https://jans.io/trace/execution_id` |
| `execution_authority` | `Audit-Execution-Authority` | `audit.execution_authority` | `https://jans.io/trace/execution_authority` |

The Auth Server owns the token-claim column. When an execution context is already known at token-issuance time, the Auth Server **MAY** (and, for deployments that want the strongest carrier, **SHOULD**) stamp `https://jans.io/trace/execution_id` and `https://jans.io/trace/execution_authority` into the issued access token's claims. The two values travel together (the MVP requires it). A downstream Cedarling `AUTHORIZATION_DECISION` or enforcement-point `CAPABILITY_INVOKED` made under that token then reads the pair from the validated token and stamps it into the record it signs — satisfying the MVP's required `trace.trace_execution_id` / `trace.execution_authority` without each producer independently discovering the id.

### 3.1 Mechanism: the Update Token interception script

The Auth Server already exposes the **Update Token** interception script (configured via `updateTokenScriptDns`; see `research/jans-auth-server-docs.txt`), whose documented purpose is to add data into an issued OAuth token. That is exactly the hook for this capability — no core token-path change is required:

- When the issuing context carries a known `(execution_authority, trace_execution_id)`, the Update Token script adds the two claims above to the access token.
- When no execution context is known (the common case for an ordinary login or token request that is not part of a governed execution), the script adds **nothing** — the claims are simply absent, and the Auth Server never fabricates a `trace_execution_id`. The MVP's execution-initiator rule is explicit that Cedarling and Lock do not mint these identifiers; neither does the Auth Server.

Where the execution context comes from (an upstream agent runtime / workflow engine / gateway that initiated the execution and passed the pair in via `Audit-Trace-ID`/`Audit-Execution-Authority` or baggage) is a deployment concern; the Auth Server's job is only to copy a known pair into the signed token so the correlation becomes available on the strongest carrier.

### 3.2 Trust boundary (unchanged from the MVP's rule)

Per the MVP propagation rules, a **signed token claim is a stronger binding than an unsigned header or baggage**, but the token's issuer and signature must still be validated by whoever relies on it, and unsigned carriers remain correlation hints. The Auth Server stamping the pair into a signed token does not make the *values themselves* authoritative — it makes them tamper-evidently attributable to the Auth Server as issuer. A trusted ingress component should still validate or replace externally-supplied `Audit-*` headers rather than forwarding them blindly, exactly as the MVP specifies; the Auth Server does not change that rule, it just provides the token-claim carrier.

## 4. What the Auth Server does NOT need for the MVP

To keep the MVP boundary unambiguous, the following full-design items are **out of scope for the MVP** and are specified in `auth-server-trace-design.md` for later phases:

- **No `AUTHENTICATION_EVENT` records.** No signed authentication evidence, no `outcome`/`auth_method`/`acr`/`amr` TRACE payload. The existing audit log (`SESSION_AUTHENTICATED`, etc., via `enabledOAuthAuditLogging`) is unchanged and is **not** a TRACE record.
- **No producer key, producer chain, or genesis.** Because the Auth Server signs no TRACE records in the MVP, it needs no registered Ed25519 TRACE producer key, no `producer_chain_id` / `sequence_number` / `prev_record_hash` state, and no chain-genesis pre-registration. (Contrast Cedarling and the enforcement point, which do, per the MVP.)
- **No token-exchange bootstrap `EXECUTION_STARTED`.** Originating an execution's evidence chain at RFC 8693 token exchange, binding `source_token_fingerprint` / `initial_capability_constraints` / `exchange_context`, is deferred with the rest of the lifecycle and token-lineage features.
- **No unattributed-evidence / correlation-backfill role.** The MVP requires `trace_execution_id` at ingestion, so the "authenticate before any execution exists, correlate later" model does not apply in the MVP.
- **No session-as-evidence-key, no `session_issuer` binding, no `human_sponsor` TRACE field.** These accompany `AUTHENTICATION_EVENT`, which is deferred.

A deployment therefore reaches full MVP functionality with **zero** Auth Server TRACE-record work, and only an optional Update-Token claim-stamping step to make the signed-token correlation carrier available.

## 5. Configuration (MVP subset)

Only the claim-stamping capability is MVP-relevant. Reusing the Auth Server's configuration-property convention, a single opt-in property gates it, disabled by default so existing deployments are unaffected:

| Property | Meaning | Default |
|---|---|---|
| `traceStampExecutionIdInTokens` | When an execution context `(execution_authority, trace_execution_id)` is known at issuance, stamp `https://jans.io/trace/execution_id` and `https://jans.io/trace/execution_authority` into the issued access token (via the Update Token script). | `false` |

The record-producing properties from the full design — `enabledTraceEmission`, `traceProducerId`, `traceSigningKey`, `traceChainGenesis`, `traceEmitTokenExchangeBootstrap`, `traceEndpoint` — are **not needed for the MVP** (the Auth Server emits no records and talks to no Lock ingestion endpoint). They belong to the post-MVP phases in `auth-server-trace-design.md`.

## 6. Acceptance criteria (MVP)

The Auth Server's MVP TRACE support is complete when:

1. With `traceStampExecutionIdInTokens` disabled (default), the Auth Server behaves exactly as today — no new claims, no new endpoints, no behavior change.
2. With it enabled and a known execution context at issuance, an issued access token carries `https://jans.io/trace/execution_id` and `https://jans.io/trace/execution_authority`, and the two are present together or not at all.
3. With it enabled but **no** known execution context, the token carries neither claim — the Auth Server never fabricates a `trace_execution_id`.
4. The claim values, being inside a signed token, are tamper-evidently attributable to the Auth Server as issuer; a relying producer still validates the token's issuer and signature before using them, and treats unsigned `Audit-*` headers only as hints.
5. The Auth Server signs no TRACE records, registers no TRACE producer key, and maintains no producer chain for the MVP.

## 7. Phased path (how this grows into the full design)

The MVP is Phase 0–1 of the full `auth-server-trace-design.md` adoption path, trimmed to the claim-stamping half of its Phase 2:

- **MVP (this document).** Optional token-claim stamping of `(execution_authority, trace_execution_id)` via the Update Token script. No records, no key, no chain.
- **Post-MVP — signed authentication evidence.** Add the producer key, per-node chain, and `AUTHENTICATION_EVENT` assembly/signing (full design Phase 1), once the Lock catalog admits authentication events and the unattributed-evidence/correlation-backfill path exists.
- **Post-MVP — execution origination.** Emit the token-exchange bootstrap `EXECUTION_STARTED` (full design Phase 2), once lifecycle events and token-exchange lineage are in scope.
- **Post-MVP — high assurance.** Chain-genesis pre-registration and lineage checkpoints (full design Phase 3).

Each step is additive over the same signed-record foundation and leaves the authentication and token hot paths untouched, matching the full design's incremental philosophy.

## References

- `Lock-Server-TRACE-MVP-Design.md` — the Lock Server MVP profile: three-kind event catalog, required `(execution_authority, trace_execution_id)` at ingestion, canonical propagation wire profile (header / baggage / token-claim carriers), execution-initiator rule, and the explicit deferral of authentication/lifecycle/backfill events.
- `auth-server-trace-design.md` — the full Auth Server producer design this MVP subsets (`AUTHENTICATION_EVENT`, token-exchange bootstrap `EXECUTION_STARTED`, producer key/chain/genesis, phased adoption).
- `design.md` — the full TRACE design (record model, event-kind schemas, correlation and propagation model).
- `research/jans-auth-server-docs.txt` — Auth Server audit logging (`enabledOAuthAuditLogging`), Update Token interception script (`updateTokenScriptDns`), RFC 8693 token exchange, ACR/AMR, sessions, DPoP.
