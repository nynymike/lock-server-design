# Jans FIDO Server TRACE Support — MVP Design

## 1. Purpose

This document specifies what the Janssen FIDO2 Server must do to support the **Lock Server TRACE MVP** defined in `Lock-Server-TRACE-MVP-Design.md`. It is the MVP-scoped companion to `fido-trace-design.md` (the full design) and parallels the Lock Server MVP's deliberately narrow profile.

As with the Auth Server MVP companion, the headline is a scoping one, stated up front because it settles the rest:

> **In the Lock Server MVP, the FIDO Server has no role.** The MVP event catalog is exactly three kinds — `AUTHORIZATION_DECISION`, `CAPABILITY_INVOKED`, `RUNTIME_EFFECT` — and it explicitly defers authentication and FIDO events. The FIDO Server's only TRACE contribution in the full design is the **`FIDO_CEREMONY`** record, which is **outside the MVP catalog**. The FIDO Server therefore signs **no TRACE records in the MVP**, maintains no producer key or chain for it, and — unlike the Auth Server — has no correlation-propagation role either, because it mints no tokens.

A deployment can run the complete Lock Server MVP with the FIDO Server **entirely unchanged**. Its TRACE support is a Phase-1-and-later effort, specified in full in `fido-trace-design.md`.

Scope of this document:

- Why the FIDO Server produces no MVP TRACE records, stated against the MVP event catalog and correlation rules.
- Why it has no fallback MVP role (no token-minting / correlation-propagation, unlike the Auth Server).
- The one indirect touchpoint (a FIDO `session_id`, if later carried), and what is deferred to the post-MVP phases.

Non-goals: this document does not redefine the TRACE record model or the Lock ingestion pipeline (owned by `design.md` and profiled by `Lock-Server-TRACE-MVP-Design.md`), and it does not restate the full FIDO producer design (owned by `fido-trace-design.md`).

## 2. MVP scope check: what the MVP needs from the FIDO Server

The Lock Server MVP (`Lock-Server-TRACE-MVP-Design.md` §3, §7.2) fixes these boundaries that bear on the FIDO Server:

- **Event catalog is three kinds only.** `AUTHORIZATION_DECISION` (Cedarling/PDP), `CAPABILITY_INVOKED` (PEP/gateway), `RUNTIME_EFFECT` (target/observer). The MVP states verbatim: "Authentication, FIDO, lifecycle, correlation-backfill, delegation, intent, approval, and transition events are deferred to later phases." `FIDO_CEREMONY` is explicitly among the deferred.
- **`trace_execution_id` is required at ingestion.** The MVP "deliberately avoids correlation-backfill behavior" and has **no unattributed-evidence path**. A `FIDO_CEREMONY`, by its nature, resolves *before* any governed execution exists (the human authenticates first), so it is the canonical unattributed-evidence case — a model the MVP does not support.
- **Session correlation is deferred.** The MVP's indexes (`Lock-Server-TRACE-MVP-Design.md` §13) include execution, record, producer-chain, capability, token, and receipt — "Session, workload, transaction, assessment, checkpoint, and graph-traversal indexes may be added in later phases." The FIDO Server's defining correlation key, the required-non-null `session_id` on a `FIDO_CEREMONY`, has no MVP home.

Mapping those against the FIDO Server's full-design responsibilities:

| Full-design FIDO Server responsibility | In the MVP? | Why |
|---|---|---|
| Sign `FIDO_CEREMONY` records | **No** | `FIDO_CEREMONY` is not in the MVP's three-kind catalog; FIDO events are explicitly deferred. |
| Maintain a producer key, producer chain, genesis | **No** | Only needed to *sign records*; the FIDO Server signs none in the MVP, so no producer key, chain, `producer_chain_id`, sequence, or genesis is required of it. |
| Emit `ABANDONED` ceremonies from the abandonment sweep | **No** | A `FIDO_CEREMONY` variant; deferred with the rest of the kind. |
| Act as **unattributed-evidence** source correlated later by `session_id` | **No** | The MVP has no unattributed/backfill path and no session index; ceremony-before-execution correlation is a deferred feature. |
| Carry correlation context in a credential/token | **No** | The FIDO Server mints no OAuth/OIDC tokens — it verifies WebAuthn ceremonies — so it has no token-claim carrier role (this is the Auth Server's job, see `auth-server-trace-design-MVP.md`). |

The FIDO Server has **no** MVP-relevant capability — not even the optional correlation-stamping role the Auth Server has — because every one of its TRACE contributions is a deferred event kind and it is not on the token-minting path that carries the MVP's required `(execution_authority, trace_execution_id)`.

## 3. Why there is no fallback MVP role

It is worth being explicit, since a reader might expect symmetry with the Auth Server MVP. The Auth Server retains one small MVP role — stamping `(execution_authority, trace_execution_id)` into issued token claims — because it is the component that mints tokens, and token claims are one of the MVP's three canonical correlation carriers (`Lock-Server-TRACE-MVP-Design.md` §7.1). The FIDO Server has no analogous role:

- It issues **no OAuth/OIDC tokens**; a WebAuthn assertion/attestation is not a correlation carrier in the MVP's wire profile.
- It is **not an execution initiator**: a FIDO ceremony is a low-level cryptographic step inside an authentication flow, not the creation of a governed unit of work, so it never mints `(execution_authority, trace_execution_id)`.
- Its evidence is **authentication evidence**, which the MVP defers wholesale.

So the correct MVP posture for the FIDO Server is: do nothing. The MVP's capability-governance flow (`authorization decision → capability invocation → optional runtime effect`) does not traverse the FIDO Server at all.

## 4. What the FIDO Server does NOT need for the MVP

To keep the boundary unambiguous, the following full-design items are **out of scope for the MVP** and are specified in `fido-trace-design.md` for later phases:

- **No `FIDO_CEREMONY` records** (`REGISTRATION`/`ASSERTION`, `SUCCESS`/`FAILURE`/`ABANDONED`). No signed ceremony evidence, no `ceremony_type`/`ceremony_outcome`/`authenticator_attachment`/`credential_id_hash` TRACE payload. The existing passkey telemetry and trust diagnostics are unchanged and are **not** TRACE records.
- **No producer key, producer chain, or genesis.** Because the FIDO Server signs no TRACE records in the MVP, it needs no registered Ed25519 TRACE producer key, no `producer_chain_id` / `sequence_number` / `prev_record_hash` state, no per-node chain, and no chain-genesis pre-registration or Producer-Key Authorization Statement.
- **No abandonment-sweep TRACE emission.** The `ABANDONED`-from-sweep path is part of `FIDO_CEREMONY`, deferred.
- **No session-as-evidence-key role.** The required-non-null `FIDO_CEREMONY` `session_id`, `session_issuer` binding, and `amr`-cross-reference to the Auth Server's authentication evidence all accompany the deferred `FIDO_CEREMONY`.
- **No unattributed-evidence / correlation-backfill role.** The MVP requires `trace_execution_id` at ingestion.

## 5. Configuration (MVP)

**None.** The MVP introduces no FIDO Server configuration. The full design's opt-in properties — `fido2TraceEnabled`, `fido2TraceProducerId`, `fido2TraceSigningKey`, `fido2TraceChainGenesis`, `fido2TraceIncludeCredentialIdHash`, `fido2TraceIncludeAttestationDetail`, `fido2TraceEndpoint` — are all Phase-1-and-later and are specified in `fido-trace-design.md`. The existing `fido2Metrics*` telemetry and trust-diagnostics configuration is untouched.

## 6. Acceptance criteria (MVP)

The FIDO Server's MVP posture is correct when:

1. The FIDO Server behaves exactly as today — no TRACE records emitted, no TRACE producer key, no producer chain, no Lock ingestion traffic, and no new configuration.
2. The Lock Server MVP reaches full functionality (its `authorization decision → capability invocation → optional runtime effect` path) without any FIDO Server participation.
3. No MVP acceptance criterion in `Lock-Server-TRACE-MVP-Design.md` §15 depends on a FIDO Server record (confirmed: the MVP catalog and acceptance tests reference only `AUTHORIZATION_DECISION`, `CAPABILITY_INVOKED`, and `RUNTIME_EFFECT`).

## 7. Phased path (how FIDO support begins after the MVP)

The FIDO Server enters TRACE at the full design's Phase 1, once the Lock catalog admits authentication/FIDO events and the unattributed-evidence/correlation-backfill and session-index features exist:

- **MVP (this document).** No FIDO Server TRACE work.
- **Post-MVP — signed, sequenced ceremonies** (full design Phase 1). Add the producer key, per-node chain, `FIDO_CEREMONY` assembly/signing (`REGISTRATION`/`ASSERTION`, `SUCCESS`/`FAILURE`), plus `ABANDONED` from the abandonment sweep, with `first_observed` genesis — attributable, tamper-evident, session-correlated ceremony evidence.
- **Post-MVP — richer ceremony context** (full design Phase 2). `authenticator_attachment`, `credential_id_hash`, and optional signed attestation/MDS-trust detail.
- **Post-MVP — high assurance** (full design Phase 3). Chain-genesis pre-registration and lineage checkpoints.

Each step is additive over the same signed-record foundation and leaves WebAuthn verification untouched, matching the full design's incremental philosophy.

## References

- `Lock-Server-TRACE-MVP-Design.md` — the Lock Server MVP profile: three-kind event catalog (with authentication/FIDO events explicitly deferred), required `trace_execution_id` at ingestion with no unattributed-evidence path, and the deferred session index.
- `fido-trace-design.md` — the full FIDO Server producer design this MVP subsets (`FIDO_CEREMONY`, producer key/chain/genesis, abandonment-sweep emission, phased adoption).
- `auth-server-trace-design-MVP.md` — the Auth Server MVP companion, which (unlike this one) retains a small correlation-stamping role because the Auth Server mints tokens.
- `design.md` — the full TRACE design (record model, `FIDO_CEREMONY` schema, correlation and unattributed-evidence model).
- `research/fido-docs.txt` — FIDO2 server architecture, ceremony outcomes (incl. `ABANDONED`), passkey telemetry, trust diagnostics.
