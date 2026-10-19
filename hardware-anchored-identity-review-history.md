# Hardware-Anchored Identity — Review History

This document records review questions raised against
[`hardware-anchored-identity.md`](./hardware-anchored-identity.md) and the change each one
produced. It is a history, not a specification: the authoritative behaviour is in the main design
document's numbered sections, which these entries point to. Keep new review rounds here so the main
document stays a clean specification rather than a running changelog.

**Status legend.** Each item is **resolved** (the algorithm is specified *and* its guarantee is
established by a passing test) or **partially resolved** (the algorithm is specified and the failure
behaviour is defined, but the guarantee depends on crash-point / concurrency fault tests that are
not yet written or passing — see "Crash-point and concurrency fault tests" in the implementation
appendix). A partially-resolved item is design-complete but not verification-complete; do not treat
its guarantee as proven until its tests pass on every backend.

**Items currently partially resolved** (algorithm specified, tests pending):

| Item | Guarantee awaiting test | Tests |
|------|-------------------------|-------|
| Q3 — single-row attestation state | a rejection is authoritative; no issuance resurrects an overwritten approval | delayed-positive-after-rejection; crash-point on the state write |
| Q8 — staged-commit evidence durability | no persisted credential lacks evidence; no false-success record; absence never classified as abort; a paused writer cannot commit after recovery | crash-point between every durable write (issuance steps 2–5); paused-writer-resume-after-cancel; crash-mid-entity-transaction rolls back atomically → `aborted` |
| Q10 — enrollment transaction | first-enrollment state initialization; idempotent redo | first-enrollment init; crash between `KeyEnrollment` and state init |
| Q11 — evidence precedence / plural in-flight | stale positive never restores approval; bounded in-flight exposure | delayed-positive-after-rejection; plural-in-flight |
| Q6 (chain), Q8 — gapless chain under abort | voided/aborted middle position leaves no gap | voided/aborted middle-record chain test |
| Q13 — fenced verifier worker | a fenced worker never records a verdict | stale-worker insertion after fencing |
| Q14 — sign the complete record | signature covers sequence/hash/outcome; retries byte-identical | sign-once-at-resolution; reject signing incomplete content; byte-identical-retry |
| Q15 — one assessment, one client | concurrent same-`attestation_id` enrollers → exactly one wins | concurrent-same-`attestation_id` enrollment; enrollment crash-point (claim/binding/state/commit) |
| Q16 — operation-specific commit receipt | recovery decides "did operation X commit?" by receipt, not identifier existence | operation-receipt discrimination (same-identifier different-operation entity does not resolve); receipt carried on `TokenEntity`/`KeyEnrollment`/`AttestationAssessment` |
| Q17 — aborted outcome wire contract | outcome records validate per operation kind and producer; bootstrap aborts under the right key | per-(kind × outcome) schema fixtures; `credential_fingerprint` present iff `committed`; bootstrap abort as `EXECUTION_STARTED`/`jans-auth`, rejected as `CREDENTIAL_PROVISIONED`; Lock-schema compatibility confirmed |

These become **resolved** when the named tests pass. The entries below describe the raised question
and the change; the status marker on each says whether verification is complete.

## Q1. Key named in evidence ≠ hardware-protected key

**Raised.** A key named in attestation evidence is not automatically a hardware-protected key.
Putting `SHA-256(nonce ‖ key-thumbprint)` into report data binds those bytes to the report, but the
design must separately establish that the private key was generated and remains protected by the
TPM / vTPM. What is the exact certification mechanism for the chosen platform?

**Change.** The plan separates *freshness* (the nonce) from *key certification* (where the private
key lives) and requires both before a verdict can be `affirming`:

- §9.3a defines the certification mechanism per platform. For the demo platform (Azure confidential
  VM, SEV-SNP with vTPM) it is `TPM2_Certify` of `K` by the vTPM attestation key with
  `qualifyingData = nonce`. Core checks AK identity, the certify signature, `extraData == nonce`,
  `attested.name == Name(K)`, the `fixedTPM | fixedParent | sensitiveDataOrigin` attributes, and
  that the certified key material equals the `attested_key` JWK.
- The evidence format carries both parts: platform evidence and `key_certification`. §9.3 example
  and field table updated.
- Key certification is verified by **core** (`TpmCertifyVerifier`, §9.3b); the assessment stores the
  outcome as `keyCertified`, and `affirming` is impossible without it (§9.4, §9.6).
- Corrected: on Azure CVMs the guest cannot choose the SNP `REPORT_DATA`, so freshness comes from
  the `TPM2_Certify` `extraData`, not the report. (See also the later Azure AK-binding gap, §9.3a.)

## Q2. Fresh attestation does not detect a compromised agent

**Raised.** A compromised process may retain access to signing operations while the VM's launch
measurement stays acceptable. State the narrower guarantee.

**Change.** §15 opens with the guarantee stated narrowly: (1) recent appraisal of specified platform
properties under a named `policy_version`, and (2) possession of the enrolled key at each DPoP
proof. It states explicitly that this does not prove which process invoked signing, that agent
memory/prompts are intact, or that no other process can use `K`. The "agent host compromised"
failure-mode row points to agent-runtime measurement or behavioural TRACE evidence as the detection
paths.

## Q3. `latestAffirming()` can ignore a newer rejection

**Status: partially resolved** — algorithm specified (§9.7/§10.4); guarantee pending the
delayed-positive-after-rejection and state-write crash-point tests.

**Raised.** An agent could receive `contraindicated` and keep obtaining tokens with an earlier,
still-fresh positive assessment. Use the latest relevant assessment and define which failures
invalidate prior approval; a verifier outage should differ from an authenticated measurement
failure.

**Change.** Strengthened to a **single authoritative state row per `(client_id, jkt)`**
(`KeyAttestationState`) with a monotonic `revision`, separate from the append-only
`AttestationAssessment` evidence log (§9.7). A `contraindicated`/`warning` overwrites the single row
under CAS on `revision`; issuance commits with a CAS conditioned on the `revision` it evaluated, so
a rejection that commits first makes the issuance's CAS fail. The linearization point and the
rejection-vs-in-flight semantics are in §10.4. Which failures invalidate prior approval:

- authenticated platform rejections (`measurement_not_allowed`, `debug_enabled`,
  `untrusted_verifier`, `key_not_certified`) and replay signals (`nonce_mismatch`,
  `evidence_expired`) invalidate prior approval;
- `key_mismatch` is stored against the key the evidence named, so attesting an unrelated key cannot
  knock out an agent;
- `none` from `verifier_unavailable` neither invalidates nor extends prior approval;
- malformed requests store nothing.

## Q4. Core must independently enforce the evidence binding

**Raised.** Core compared a script-provided `attested_jkt` and trusted the script's `nonceVerified`
boolean, so "a script cannot mint `affirming` for a key the evidence does not name" was unsupported.
Either treat the adapter as trusted security code or have core validate the signed verifier result
and binding.

**Change.** Core now validates. §9.3b splits the work: the script calls the verifier and applies
measurement policy; **core** verifies the `AttestationResultJWT` signature/issuer/expiry against a
server-configured verifier profile, compares the nonce to the persisted challenge, derives the
attested key itself, verifies the `TPM2_Certify` chain (`TpmCertifyVerifier`), and sets the final
status to the minimum of its binding verdict and the script's policy verdict. The script result API
lost its `attestedJwk`/`nonceVerified`/`keyCertified` setters and exposes core-verified claims
read-only. (See also Q1's later AK-binding refinement in §9.3a.)

## Q5. Attestation/enrollment cannot share every execution id

**Raised.** Attestation and enrollment occur before execution and may support many later
executions; keep their own record identifiers. A fresh `txn` per token issuance also fragments one
execution across renewals. Define execution scope independently of credential lifetime.

**Change.** §3 defines three scopes (execution, token lifetime, key lifecycle) with their own
identifiers; the execution is identified by `(trace_execution_id, execution_authority)` (with `txn`
as an application alias). An execution is opened by the ID-JAG exchange or the first `/token` of an
autonomous agent that carries no execution id; the server mints the pair, returns it, and accepts it
on renewals while the execution is open and bound to the same client/principal (`jansTraceExecution`
registry, §10.8). Attestation/enrollment records are lifecycle records with their own
`trace_execution_id` scope (`att:<attestation_id>`, `enroll:<client_id>`), referenced by
`parent_record_ids` (§11.2).

## Q6. The human in `act` reverses the delegation meaning

**Raised.** With the agent as `sub`, Alice in `act` says Alice is acting for the agent; `may_act` is
not a generic delegator field either. Preserve the SPIFFE agent subject and define a separate,
explicit delegation reference.

**Change.** `act` is removed. The SVID keeps the SPIFFE ID as `sub` and carries a dedicated
`delegation` claim (`principal_iss`, `principal_sub`, `credential_type`, `credential_id`). §§6, 10.5,
10.7, the update-token restriction, tests, failure modes, and the specs table were updated; the
specs table records that RFC 8693 `act` / `may_act` were considered and not used.

## Q7. The challenge lifecycle contradicted itself

**Raised.** Core consumed the challenge before calling the verifier, but a verifier outage
supposedly left it unconsumed. Specify an atomic state machine with controlled retry.

**Change.** §9.3c replaces the cache entry with a persistent `AttestationChallenge` and a state
machine `pending → processing → completed`, with `processing → pending` only for infrastructure
failures that produced no verdict, bounded by `attestationChallengeMaxRetries`, keeping the original
nonce. A node lease and a repair timer recover from crashes mid-verification; the losing side of a
concurrent claim gets `challenge_in_progress` without a fresh nonce; `completed` is terminal.

## Q8. Evidence durability was only partially specified

**Status: partially resolved** — algorithm and failure behaviour specified (§11.3), including the
embedded per-operation commit receipt (Q16) and writer cancellation/fencing; guarantee pending the
crash-point-between-every-durable-write, voided/aborted-middle-record, and
paused-writer-resume-after-cancel tests.

**Raised.** Updating chain state and the outbox together prevents some chain failures but does not
ensure every successful issuance has an evidence record unless issuance and evidence persistence
have a defined commit relationship. Explain crash recovery, duplicate delivery, and outbox
exhaustion.

**Change.** §11.3 specifies three axes:

- **Append protocol.** The first answer used a multi-writer unique-index + tail-CAS scheme. Two
  further rounds found it unsound — the fence was checked *after* the authoritative insert (a stale
  writer could commit a record then merely fail its tail update), and a writer that lost the insert
  "adopted" a colliding record without proving it belonged to the same operation. The current
  design (§11.3) replaces it with a **per-chain single-writer journal**: issuance threads write
  unordered `operation_id`-keyed intake rows and never contend for a chain position; one
  fenced-lease journal writer per chain assigns sequence numbers serially; the `epoch` fence is
  enforced *in* the authoritative guarded insert (a stale writer cannot create a row at all); and a
  record is matched to its operation by stored `operation_id`, never adopted.
- **Hold delivery until commit.** The signed record is `staged`, not published, until the
  credential's entity write is confirmed committed (a `staged → committed` CAS flip), closing the
  false-success-evidence hole. "Persisted credential" and "response received by the client" are
  distinguished; the record attests only the former.
- **Reconciliation witness bound into one transaction.** Successive rounds found that any *separate*
  marker could be lost after the entity committed, so absence of the marker was mistaken for
  non-commit. The current design (§11.3) embeds an **operation commit receipt (`operation_id` +
  `record_id`) inside the entity itself** — `TokenEntity`, `KeyEnrollment` (enrollment), or
  `AttestationAssessment` (appraisal) — and binds the entity, the `operation_id`-keyed `IssuanceLog`,
  and the `staged → committed` flip into **one SQL transaction**, so a committed operation always
  leaves a token-outliving witness and a non-commit leaves none. Recovery decides on the **receipt**
  (did *this* `operation_id` commit?), not on the entity's identifiers (Q16). A paused writer is
  **fenced by cancellation** before recovery records a terminal outcome, so it cannot commit after
  recovery acts. Because commit is one transaction, absence of the `IssuanceLog` past the resolution
  wait is **decidable non-commit** — outcomes are therefore committed / aborted / unresolved, with
  no undecidable case. (Earlier rounds, when LDAP was a supported backend, carried a fourth
  `indeterminate` outcome for the case where a separate marker write could be lost after an
  LDAP entity committed; the SQL-only decision, Q18, removed it.)
- **Gapless chain: aborted positions are delivered, not dropped.** A further round noted that a
  sequence number is allocated at stage time, so a never-committed position that was simply voided
  would leave a hole in the chain Lock receives. The design now chooses the **"chain the operation
  with explicit aborted outcomes"** model: every allocated position is delivered — a committed one
  as the success record, a never-committed one as a signed aborted-outcome record at the same
  position. `prev_record_hash` is bound at resolution over the predecessor's *delivered* digest
  (not at stage time, since the predecessor's final content is not yet known), and delivery is
  strictly in sequence order. The tail pointer therefore no longer caches a record hash (§11.3).

Delivery to Lock is at-least-once (idempotent on `record_id`; a content-mismatch `409` is an error,
never treated as delivered).

## Q9. Remove the extra assessment JWT

**Raised.** jans already stores the assessment, DCR can reference its id, and `/token` looks it up by
client and key; the SVID and the TRACE record already communicate acceptance. A portable assessment
JWT is useful only when another system must consume it independently.

**Change.** Removed. §9.6 lists how each consumer learns the verdict without a token: the agent from
the `/attestation` response, DCR from the `attestation_id`, `/token` from the `(client_id, jkt)`
lookup, relying parties from the SVID's `attestation` claim, auditors from the
`CREDENTIAL_PROVISIONED` record. The only signed attestation object left is the platform verifier's
`AttestationResultJWT`. §9.6 notes the one case that would justify a portable token later and the
EAT shape it would take.

## Q10. Enrollment had no complete transition into authoritative state

**Status: partially resolved** — enrollment transaction specified (§9.5), including the atomic
`attestation_id` claim that enforces one-assessment-one-client (Q15); guarantee pending the
first-enrollment-init, concurrent-enrollment, and enrollment crash-point tests.

**Raised.** A pre-enrollment attestation has no `client_id` and requires no DPoP, so it is
`supersedesEligible=false`; but only a `supersedesEligible=true` assessment could populate
`KeyAttestationState`, and issuance requires that state — so a freshly enrolled client could never
issue. Separately, DCR said to set `clientId` on the assessment while §9.7 said assessments are
immutable (a direct contradiction).

**Change (§§9.5, 9.7, 10.4).** Enrollment is now an explicit, idempotent **enrollment transaction**:
(1) atomically **claim** the assessment via a `KeyEnrollmentClaim` keyed by `attestation_id`
(insert-conditioned-on-absence, the uniqueness point — see Q15); (2) verify the `/register` DPoP
proof against the assessed key; (3) leave the assessment **immutable** — no `clientId` back-fill;
(4) create a separate **`KeyEnrollment`** binding `(clientId, jkt) → attestationId`; (5)
**initialize** `KeyAttestationState(clientId, jkt)` at `revision = 0`, authorized by the DCR proof
rather than by `supersedesEligible`; (6) commit the claim, record the client attribute, and emit the
enrollment TRACE record. `supersedesEligible` now governs only *overwriting* an existing client's
state, not *initializing* a key's first state; the write-side CAS table gained a distinct
enrollment-initialization row. One assessment enrolls exactly one client — enforced by the atomic
claim, not a lookup (`assessment_already_enrolled` for a losing concurrent enroller) — and adding a
replacement key reuses the same transaction (Q15).

## Q11. Attestation ordering needs rules beyond CAS

**Status: partially resolved** — `appraisalGeneration` precedence and the plural-in-flight exposure
specified (§9.3/§10.4); guarantee pending the delayed-positive-after-rejection and plural-in-flight
tests.

**Raised.** A monotonic `revision` orders *writes* but not which *evidence* should win: an older
positive appraisal can finish slowly, lose a CAS to a newer rejection, retry, and overwrite that
rejection — restoring approval from stale evidence. Separately, with per-issuance freshness disabled
the text understated the race: multiple concurrent requests can all pass `stillCurrent(r)` before a
rejection and all finish, so the exposure is plural, not one SVID.

**Change (§§9.3, 9.7, 10.4).** Added a per-key **`appraisalGeneration`** stamped at challenge
issuance (monotonic, independent of wall-clock), carried challenge → assessment → state. The
write-side guard now admits an overwrite **only if its generation is strictly newer** than the row's
— so a stale `affirming` that loses and retries is dropped, never restoring approval. `revision`
orders writes; `appraisalGeneration` orders evidence. The default-mode exposure is restated honestly
as **plural already-authorized in-flight issuances** that complete after a rejection (bounded by SVID
TTL; collapsed to one by `attestationRequireFreshPerIssuance`/a `critical` tier), and the
authorization point is related to entity persistence and evidence commit as three ordered points — a
rejection governs only issuances not yet past the first.

## Q12. Privacy claims stronger than the token format supports

**Raised.** Pairwise human subjects do not prevent correlation if tokens disclose the same ID-JAG
`credential_id` across audiences, and the stable agent `sub` and hardware `cnf.jkt` remain
correlation handles. More directly, "a token is readable only by the one RP it was scoped to" is
wrong: audience restriction controls acceptance, not readability — a signed JWT is not encrypted.

**Change (§§10.2, 10.5, 10.10).** Replaced the "readable only by" sentence with: *each token is
intended for one resource server; anyone who obtains the signed JWT can read its claims* — the
privacy lever is minimization, not confidentiality. Made the delegation credential reference
**audience-specific** (`credential_ref`, a per-`(audience, ID-JAG)` opaque value; the raw `jti` is
never put in the token), so it no longer re-links the human across audiences. Restated pairwise
identifiers as **reducing the human-identity correlation path**, explicitly **not** promising
general unlinkability, and named the residual handles: the agent `sub` and `cnf.jkt` are stable
across audiences by design (the agent is one identity), so colluding RPs can still see "the same
agent," just not which human or the delegation credential.

## Q13. A batch of precision fixes across attestation, delegation, privacy, and signing

**Status: mostly resolved** — items (2)–(7) are specified and testable directly; item (1), the
fenced verifier worker, is **partially resolved** pending the stale-worker-insertion-after-fencing
crash test.

**Raised (seven items).** (1) §9.3c claimed a verdict and `completed` are "written in one operation"
though challenge, assessment, state, and outbox are separate entities — and a verifier worker whose
lease expired was not fenced. (2) §9.3a / appendix treated a missing Azure AK binding as grounds to
*auto*-fall back to `measured_guest`. (3) §10.8 principal binding used only `iss`+`sub`, ignoring
tenant scope. (4) §10.9 called `BE=0` a hardware binding. (5) §§8, 10.5 accepted any asymmetric
algorithm ("not HMAC"). (6) §§10.8/10.6 stopped new issuance at delegation expiry but left
outstanding SVIDs usable. (7) §10.10 defaulted execution disclosure to both "omitted" and
"same_domain."

**Change.** (1) §9.3c: the worker holds a lease `epoch`; the assessment / `completed` / state writes
are separate, recoverable, **epoch-guarded** transitions (a fenced worker cannot write any of them),
resolved by `challenge_id` on recovery. (2) §9.3a: `key_binding_strength` is three-valued —
`certified` / `measured_guest` / **`none`** — and a failed AK binding downgrades to `measured_guest`
**only if** that weaker binding is independently shown, else `none` (`binding_unestablished`) and
issuance does not proceed; no silent relabel. (3) §10.8: added `principalTenant` to the binding and
registry, required for issuers that scope subjects per tenant (per the ID-JAG draft). (4) §10.9:
`BE=0` = **single-device credential**; hardware protection is a separate attestation/AAGUID/MDS
signal, stated separately. (5) §§8, 10.5: enforce the SPIFFE JWT-SVID **algorithm allowlist**
(`RS*`/`ES*`/`PS*`) and permitted JOSE headers, on both the bundle and the verifier — an explicit
allowlist, not a denylist. (6) §10.6: clamp a delegated SVID's `exp` to `≤ delegationExpiresAt`, so
delegation expiry revokes access, not merely new issuance. (7) §10.10: chose **omitted** as the
no-profile execution-disclosure default (aligned with `svidDefaultClaims`), with `same_domain` the
granularity once an audience opts in; aligned table, config, and tests.

## Q14. Signing happened before the record was complete

**Status: partially resolved** — algorithm specified (§11.3); guarantee pending the
sign-once-at-resolution and byte-identical-retry tests.

**Raised.** Step 1 signed the success record, but `sequence_number`, `prev_record_hash`, and the
final outcome were assigned later. If those fields are signature-covered the early signature cannot
authenticate the final record; if they are excluded, the chain-position/linkage protection is
unqualified-but-false.

**Change (§11.3).** The intake row is now explicitly **unsigned** event content (no sequence, hash,
or outcome). The complete TRACE record is **finalized and signed once, at resolution** (new step 7),
after its `sequence_number`, `prev_record_hash`, and `provisioning_outcome` are known, so the single
signature covers position, linkage, and outcome with no qualification. The canonical signed bytes
are persisted on the outbox entry before delivery and re-sent **byte-identically** on every retry
(so a `409` content-mismatch cannot arise from a retry). An optional **signed intent object** is
defined as a separate, distinctly-typed artifact for deployments that want an attempt-time
signature — never the record's signature, and not emitted in v1.

## Q15. "One assessment enrolls one client" had no atomic mechanism; key replacement under-specified

**Status: partially resolved** — atomic claim and the two replacement proofs specified (§9.5);
guarantee pending the concurrent-same-`attestation_id` enrollment and enrollment crash-point tests.

**Raised.** The enrollment transaction asserted that a second enrollment naming the same
`attestation_id` for a different `client_id` is refused, but the `KeyEnrollment` binding was keyed
by `(clientId, jkt)`, so two concurrent registrations with the same `attestation_id` but different
client IDs would create two distinct bindings — neither insert conflicts, and a lookup of "already
enrolled?" followed by an insert is not atomic under concurrency. Separately, key replacement said
it both *reuses the enrollment transaction* (which demands a proof from the **new** key) and must be
*old-key-authorized* (a proof from the **old** key), without specifying both proofs or their formats.

**Change (§9.5).** Enrollment now begins with an atomic claim: a **`KeyEnrollmentClaim`** keyed by
`attestation_id` (not `(clientId, jkt)`), inserted **conditioned on absence** as step 1, is the
single serialization point — concurrent enrollers naming the same `attestation_id` race on one
insert and exactly one wins; the loser is refused `assessment_already_enrolled` by the conflicting
write, not by a stale lookup. The claim carries an `operationId` (so only the original enroller can
complete a crashed transaction) and a `pending`/`committed` state (the durable recovery marker);
recovery is re-specified across claim → `KeyEnrollment` → `KeyAttestationState` → claim-commit. Key
replacement now names **two distinct proofs** with formats: a **new-key DPoP proof** over the added
key (`htm=POST`/`htu`/`iat`/`jti`, `jwk` thumbprint = `attested_jkt`, carried as the request's
`DPoP` header) that initializes the added key's state, and **old-key authorization** of the
`updateClient` mutation (a DPoP proof over a currently-trusted key with the `ath` claim, or a
`private_key_jwt` assertion signed by the old key), both validated by `DpopService`.

## Q16. Recovery conflated "an entity exists" with "this operation committed"

**Status: partially resolved** — operation-receipt rule specified (§11.3); guarantee pending the
operation-receipt-discrimination and crash-point tests.

**Raised.** Recovery resolved a `staged` entry by probing the authoritative entity by its locator
identifiers (`jti`/`client_id`/`jkt`) and treating existence as proof of commit. But finding a
`Client`, enrolled key, or assessment with those identifiers does not prove that the *particular
operation* in the intake row committed: the entity may predate the operation (a key enrolled or an
assessment appraised earlier) or have been rewritten by a later operation sharing the identifiers.
The `TokenEntity` already carried an embedded `operation_id`, but the probe text still spoke of
"entity present," and the `IssuanceLog` was keyed by `record_id`; enrollment and appraisal — both
named in the durability invariant — had no operation-specific receipt at all.

**Change (§11.3).** Recovery now answers **"did *this* `operation_id` commit?"** rather than "does
an entity with these identifiers exist?". Every provisioning entity carries an **operation commit
receipt (`operation_id` + `record_id`) written in the same single-entity write** — `TokenEntity`,
`KeyEnrollment` (already from Q15), and `AttestationAssessment` (new `traceOperationId`/
`traceRecordId` fields). The token-outliving `IssuanceLog` is **keyed by `operation_id`**. Commit is
confirmed only when a probed entity carries *this* entry's `operation_id` in its receipt, or an
`operation_id`-keyed `IssuanceLog` row is present; a same-identifier entity bearing a different or
absent `operation_id` proves nothing about this attempt and is not read as commit. The probe table,
the witness rule, and the crash-point / reconciliation tests are all stated in terms of the receipt,
not identifier existence.

## Q17. Aborted/indeterminate outcomes were not a complete wire contract

**Status: partially resolved** — the outcome wire contract and per-producer rule are specified
(§11.2/§11.3); guarantee pending the per-(kind × outcome) schema-fixture tests and confirmation
against Lock's actual schema.

**Raised.** The design introduced a `CREDENTIAL_PROVISIONED` with `provisioning_outcome=aborted` and
no `credential_fingerprint`, but the implementation appendix still said no event-format changes were
needed, and the shape was described only in §11.3 prose — no field-level contract, no Lock schema /
validation confirmation. Two concrete gaps: (1) `provisioning_outcome` and an absent
`credential_fingerprint` *are* format additions Lock's per-kind schema must accept, even though the
`event_kind` is unchanged; (2) the generic abort rule hard-coded `CREDENTIAL_PROVISIONED`, so it did
not cover an unsuccessful **`EXECUTION_STARTED`** bootstrap — which belongs to the `jans-auth`
producer, whose key is **not** authorized to emit `CREDENTIAL_PROVISIONED`.

**Change (§11.2, §11.3, appendix).** The outcome is now an explicit wire contract: a new
`event.provisioning_outcome` discriminator (default `committed`, preserving the success shape), with
per-outcome required fields — `credential_fingerprint` **present iff `committed`**, `reason` =
`not_committed` for an abort, and the chain/identity fields carried on every outcome. (This round
defined three values, `committed`/`aborted`/`indeterminate`, the last for the case where an LDAP
entity committed but a separate marker write was lost and the token had since vanished; the SQL-only
decision, Q18, removed `indeterminate`, leaving `{committed, aborted}`.) The abort rule is restated
**per producer**: a failed issuance/enrollment/appraisal aborts as a `CREDENTIAL_PROVISIONED` under
`jans-svid-issuer`; a failed **bootstrap aborts as an `EXECUTION_STARTED` under `jans-auth`**, never
a `CREDENTIAL_PROVISIONED` (which Lock rejects for that producer key). The appendix's jans-lock row
now lists the field-level format changes as a **confirmation item against Lock's actual schema**
(resolved by a Lock-side schema update if needed, never by fabricating a fingerprint), and a new
`OutcomeRecordSchemaFixtureTest` adds a canonical fixture for **each (operation kind × outcome)**
cell, shared with Lock's conformance suite.

## Q18. SQL is the only persistence backend (Ledger drops LDAP and Couchbase)

**Status: resolved** — the design targets SQL only; the backend-portability caveats and the
LDAP-only `indeterminate` outcome are removed.

**Raised.** Ledger will not support LDAP or Couchbase; the only backend needed is SQL. Earlier
rounds had carried portability caveats because the Jans `PersistenceEntryManager` abstraction
surfaces only single-entry CAS uniformly across LDAP/SQL/Couchbase, and several guarantees were
stated as "varies by backend."

**Change (§§9.3c, 9.5, 9.7, 10.4, 11.3, appendix).** All LDAP and Couchbase references are removed
and the multi-backend caveats collapse into SQL behaviour:

- **Enrollment (§9.5)** is now **one SQL transaction** (claim insert → binding → state init →
  client attribute). The `pending`/`committed` claim lifecycle and `enrollmentClaimTimeoutSeconds`
  are gone — a crash rolls back atomically, so there is no half-enrolled state to reconcile.
  Concurrency/uniqueness is still the `attestation_id` unique-constraint insert; a losing concurrent
  enroller's transaction simply rolls back.
- **Issuance/enrollment/appraisal durability (§11.3)** binds the entity (with its `operation_id`
  receipt), the `operation_id`-keyed `IssuanceLog`, and the `staged → committed` flip into **one SQL
  transaction**. Commit is therefore always decidable: absence of the `IssuanceLog` past the
  resolution wait is decidable non-commit. The **`indeterminate` outcome is removed** (it existed
  only for the LDAP lost-marker-then-token-deleted case), so `provisioning_outcome ∈ {committed,
  aborted}`, and `ldapRetainTokenUntilReconciled` is removed.
- **Single-row `KeyAttestationState` CAS (§9.7/§10.4)** and the **verifier-worker ordered writes
  (§9.3c)** keep their shape — the single-row CAS is the simplest correct design, and the worker's
  three writes are genuinely distinct conditional writes — but the `PersistenceEntryManager`
  abstraction-limit justification (which only made sense across heterogeneous backends) is dropped.
- The CAS implementation notes collapse to the SQL form (`UPDATE … WHERE revision = :r`,
  `INSERT … WHERE … epoch = :myEpoch`), and the fault tests run on SQL only (including a clustered
  configuration), now also asserting mid-transaction rollback.

## Later review rounds

Subsequent review rounds refined the above into the current design; the material changes are already
folded into the numbered sections of the main document (notably the §9.3c fenced verifier worker,
the §9.5 enrollment transaction, the §9.7/§10.4 single-row state model with `revision` +
`appraisalGeneration`, the §11.3 append/commit protocol, the §9.3a Azure AK-binding gap and
three-valued `key_binding_strength`, the §10.5/§8 JWT-SVID algorithm allowlist, the §10.6/§10.8
delegation-expiry clamp and tenant-scoped principal binding, the §10.9 BE/BS-vs-hardware
distinction, the §10.10 token-privacy scope, the §11.3 sign-once-at-resolution rule, the §11.2/§11.3
per-producer outcome wire contract (`provisioning_outcome`, bootstrap aborts as `EXECUTION_STARTED`),
the SQL-only backend reduction (§§9.5/11.3, which removed the `indeterminate` outcome and the
LDAP/Couchbase portability caveats), and the §16.1 key-revocation delay). This history preserves the
original questions that drove them; for current behaviour, read the main document.
