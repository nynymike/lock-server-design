# Lock Server TRACE — Design

Design documents for adding **TRACE evidence collection** to the Janssen **Lock Server**.

TRACE records are signed, immutable statements about security-relevant events — authentication, authorization decisions, capability invocations, delegation, trust-boundary crossings, and observed runtime effects. Lock Server verifies these records, preserves each producer's original signed assertion unchanged, and correlates them into a verifiable **evidence graph** organized around a governed execution (`trace_execution_id`).

The goal is evidence that can be checked by someone **outside the producer's trust boundary**: attributable (who signed it), tamper-evident (the bytes have not changed), correlatable (which records belong to the same execution), and honest about what is *not* established (what is missing, what was not verified, which trust assumptions remain). A valid signature is necessary but is never treated as proof that a policy ran, an action occurred, or an effect was authorized.

This repository is **design documentation only** — there is no implementation here.

## Where to start

- **New to the project?** Read the [full design](design.md) overview, then the [MVP design](Lock-Server-TRACE-MVP-Design.md).
- **Implementing the first release?** Start from the [MVP design](Lock-Server-TRACE-MVP-Design.md) and the [phased implementation plan](phased-implementation-plan.md); Phase 1 *is* the MVP.
- **Integrating a producer** (Cedarling, Auth Server, FIDO Server)? Read that producer's companion doc below.

## Core design

| Document | What it covers |
|---|---|
| [design.md](design.md) | **The full TRACE design.** The authoritative record model, verification/settlement pipeline, evidence graph, correlation, trust tiers and the per-dimension verification vector, capability resolution, evidence-domain isolation, lineage/anchoring, correctness properties, and alignment with the TRACE standard (v0.2). |
| [Lock-Server-TRACE-MVP-Design.md](Lock-Server-TRACE-MVP-Design.md) | **The MVP profile** — the smallest useful implementation (a strict subset of the full design): signed single/bulk ingestion, evidence-domain isolation, producer-key registration, the receipt hash chain, correlation, and ingestion-time integrity flagging. |
| [phased-implementation-plan.md](phased-implementation-plan.md) | How the full design is delivered incrementally. Phase 1 = the MVP; later phases add settlement, completeness/context, and full cross-domain assurance. |
| [jans-trace-core-mvp-design.md](jans-trace-core-mvp-design.md) | The reusable **`jans-trace-core`** Rust library for the deterministic cryptographic operations (JCS canonicalization, Ed25519 signing/verification, content-digest, receipt-chain hashing) shared by producers, Lock, and independent verifiers. |

## Producer integrations

Each TRACE producer signs its own records with its own key. These companion docs map each Jans component onto the record model, with a full-design version and an MVP-scoped version.

| Producer | Produces | Full design | MVP scope |
|---|---|---|---|
| **Cedarling** (PDP) | `AUTHORIZATION_DECISION` | [cedarling-trace-design.md](cedarling-trace-design.md) | [cedarling-trace-design-MVP.md](cedarling-trace-design-MVP.md) |
| **Jans Auth Server** (OP) | `AUTHENTICATION_EVENT`, execution bootstrap | [auth-server-trace-design.md](auth-server-trace-design.md) | [auth-server-trace-design-MVP.md](auth-server-trace-design-MVP.md) |
| **Jans FIDO Server** | `FIDO_CEREMONY` | [fido-trace-design.md](fido-trace-design.md) | [fido-trace-design-MVP.md](fido-trace-design-MVP.md) |

**Producer roles in the MVP, at a glance:** Cedarling is a first-class MVP producer (it signs one of the three MVP event kinds). The Auth Server has only a thin MVP role — stamping the execution-correlation pair into issued token claims — since authentication events are deferred. The FIDO Server has no MVP role (its `FIDO_CEREMONY` is deferred). The three MVP companion docs explain each case.

## Key concepts

- **Producer vs. Lock.** Producers sign *facts they observed*; Lock derives *interpretations* (trust tier, settlement, completeness, capability resolution) and stores them **outside** the immutable signed assertion.
- **Execution, not session.** Evidence is organized around `trace_execution_id` (a governed unit of work), with human sessions as one optional dimension.
- **Enforcement separation.** `CAPABILITY_INVOKED` is signed by the enforcement point's own key, never the PDP's — even when Cedarling is embedded in the enforcing application (two producers, two keys, one process).
- **Standard alignment.** Lock emits a distinct Jans profile (`tag:jans.io,2026:trace-v1`) that extends the TRACE standard (tracked at **v0.2**); see *Alignment with TRACE v0.2* in [design.md](design.md).

## Repository layout

```
design.md                          Full TRACE design (authoritative)
Lock-Server-TRACE-MVP-Design.md    MVP profile (Phase 1)
phased-implementation-plan.md      Phased delivery plan
jans-trace-core-mvp-design.md      Shared Rust crypto library design
cedarling-trace-design*.md         Cedarling producer (full + MVP)
auth-server-trace-design*.md       Auth Server producer (full + MVP)
fido-trace-design*.md              FIDO Server producer (full + MVP)
```

The `research/` directory holds background source material (the TRACE spec, Jans component docs, and code references) used while writing these designs; it is not part of the design deliverable.
