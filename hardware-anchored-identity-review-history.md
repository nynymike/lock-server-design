# Hardware-Anchored Identity — Review History

This document records review questions raised against
[`hardware-anchored-identity.md`](./hardware-anchored-identity.md) and the change each one
produced. It is a history, not a specification: the authoritative behaviour is in the main design
document's numbered sections, which these entries point to. Keep new review rounds here so the main
document stays a clean specification rather than a running changelog.

**Status legend.** Each item is **resolved** (the algorithm is specified *and* its guarantee is
established by a passing test); **partially resolved** (the algorithm is specified and the failure
behaviour is defined, but the guarantee depends on crash-point / concurrency fault tests that are
not yet written or passing — design-complete, not verification-complete); or **algorithm
incomplete** (the design does not yet fully pin the behaviour — e.g. the fencing / crash-recovery
ordering is still being specified, so a test cannot yet be written against a settled algorithm).
An **algorithm-incomplete** item is a stronger caveat than *partially resolved*: it is **not**
design-complete, and its guarantee must not be treated as proven or even as test-ready. See
"Crash-point and concurrency fault tests" in the implementation appendix. Do not treat any
non-**resolved** guarantee as proven.

**Items currently algorithm-incomplete** (behaviour not yet fully pinned, not merely untested):

| Item | What is still open |
|------|--------------------|
| Q8 — staged-commit evidence durability (fencing + recovery) | the fence-then-resolve ordering, the paused-writer cancellation interaction with **Commit**, and the recovery drain across **Intake → Stage → Commit → Resolve-abort** are specified as a transition table (§11.3) but the cancellation/fence protocol and its recovery edges are still being nailed down; the guarantee is not yet reducible to a settled algorithm a test can pin |
| ~~Q13 — fenced verifier worker~~ | **Resolved by Q22** (algorithm now settled): the appraisal commit is a single atomic transaction (verifier call outside it; then lease re-check under row lock + assessment + state write-through + `completed` + evidence, all-or-nothing), so there are no "partial states" to order or recover. Now **partially resolved** (algorithm complete, pending the single-transaction fault test) rather than algorithm-incomplete |

**Items currently partially resolved** (algorithm specified, tests pending):

| Item | Guarantee awaiting test | Tests |
|------|-------------------------|-------|
| Q3 — single-row attestation state | a rejection is authoritative; no issuance resurrects an overwritten approval | delayed-positive-after-rejection; crash-point on the state write |
| Q10 — enrollment transaction | first-enrollment state initialization; idempotent redo | first-enrollment init; crash between `KeyEnrollment` and state init |
| Q11 — evidence precedence / plural in-flight | stale positive never restores approval; bounded in-flight exposure | delayed-positive-after-rejection; plural-in-flight |
| Q6 (chain), Q8 — gapless chain under abort | voided/aborted middle position leaves no gap | voided/aborted middle-record chain test |
| Q14 / Q25 — sign the complete record | signature covers sequence/hash/outcome; **one authoritative byte sequence** across rebuilds and concurrent finalizers | sign-once-at-resolution; reject signing incomplete content; freeze-input + install-once-CAS + adopt-winner (`signed_at`/`kid` do not drift; CAS loser adopts stored bytes) |
| Q15 — one assessment, one client | concurrent same-`attestation_id` enrollers → exactly one wins | concurrent-same-`attestation_id` enrollment; enrollment crash-point (claim/binding/state/commit) |
| Q16 — operation-specific commit receipt | recovery decides "did operation X commit?" by receipt, not identifier existence | operation-receipt discrimination (same-identifier different-operation entity does not resolve); receipt carried on `TokenEntity`/`KeyEnrollment`/`AttestationAssessment` |
| Q17 / Q21 — outcome wire contract | outcome records validate per **event kind × operation subtype × outcome**; bootstrap aborts under the right key | per-(subtype × outcome) schema fixtures; identifying artifact per the matrix (fingerprint only for SVID issuance/enrollment; appraisal and bootstrap carry none); bootstrap abort as `EXECUTION_STARTED`/`jans-auth`, rejected as `CREDENTIAL_PROVISIONED`; Lock-schema compatibility confirmed |
| Q13 / Q22 — appraisal single-transaction commit | assessment + state write-through + `completed` + evidence commit atomically; no window where a negative verdict is durable while issuance reads the old positive state | single-transaction fault test (crash during verifier call / mid-transaction leaves nothing durable; fenced worker aborts at the lease re-check; superseded-generation skips write-through; `none`-outage writes evidence only) |
| Q15 / Q23 — key-replacement wire format | the key change is an RFC 7592 `PUT`; old-key auth, new-key possession, and the signed mutation occupy distinct, defined locations | `RegisterValidatorTest` (`htm=PUT` accepted, `POST` rejected; `attested_key_pop` body member; `change_digest` on both proofs matches the body, mismatch → `key_change_not_signed`) |
| Q15 / Q24 — enrollment HTTP-retry idempotency | a lost-response retry keyed by client-held `(attestation_id, K)` replays the committed enrollment; a different client or wrong key is refused | enrollment HTTP-retry idempotency (lost-response replay without the internal `operationId`; `attestation_id` + proof-key == `claimedJkt` binding; crash-before-commit re-runs fresh) |

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
as an application alias). An execution is opened by jans (the Resource AS) when it **redeems** a
human's ID-JAG at `/token`, or on the first `/token` of an autonomous agent that carries no
execution id; jans mints the pair there, returns it, and accepts it on renewals while the execution
is open and bound to the same client/principal (`jansTraceExecution` registry, §10.8). The ID-JAG
is issued earlier by a separate IdP AS and carries no execution id (§5, Q19). Attestation/enrollment records are lifecycle records with their own
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

**Status: algorithm incomplete** — the §11.3 transition table specifies the happy path and the
embedded per-operation commit receipt (Q16), but the **fencing and crash-recovery** parts are not
yet a fully settled algorithm: the cancel-then-resolve ordering, the paused-writer cancellation
interaction with **Commit**, and the recovery drain across **Intake → Stage → Commit → Resolve-abort**
still need to be pinned before a test can assert the guarantee. Treat the durability guarantee as
design-incomplete, not merely untested. (The narrower gapless-chain-under-abort claim is tracked
separately as partially resolved.)

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

**Status: partially resolved** — items (2)–(7) are specified and testable directly; item (1), the
**fenced verifier worker**, was formerly *algorithm incomplete* but is now **algorithm-settled by
Q22**: the appraisal commit is a single atomic transaction (verifier call outside it; then lease
re-check under row lock + assessment + state write-through + `completed` + evidence, all-or-nothing),
which replaced the earlier "assessment → `completed` → state overwrite" ordering and its partial-state
recovery. "A fenced worker never records a verdict" now reduces to "the worker aborts at the
in-transaction `SELECT … FOR UPDATE` lease re-check," pending the single-transaction fault test.

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

> **"Re-finalizing is byte-identical" qualified by Q25.** This round leaned on signature determinism,
> but a *rebuild* after a crash can change `signed_at`, the selected `kid` (after a key rotation), or
> other generated fields, so determinism of Ed25519 alone does not reproduce the bytes. Q25 freezes
> the full signing input (including `signed_at`/`kid`) and installs the bytes once via CAS, with
> concurrent/retry finalizers adopting the stored winner — the guarantee is **one authoritative byte
> sequence, not one execution of the signer**.

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

> **Key-replacement wire format superseded by Q23.** This round assigned *both* proofs to DPoP but
> left only one `DPoP` header, never defined the "different request locations," and wrongly used
> `htm=POST` for what is an RFC 7592 `PUT`. Q23 gave the concrete wire format: old-key authentication
> in the one `DPoP` header (`htm=PUT`), new-key possession as the body member `attested_key_pop`, and
> a `change_digest` on both so the exact mutation is signed (DPoP/`private_key_jwt` do not sign the
> body).

> **Retry-idempotency mechanism superseded by Q24.** This round made the retry hinge on the claim's
> `operationId`, but that is a server-internal id the client never sees — after a lost `/register`
> response the caller cannot present it. Q24 replaced it with a client-visible authenticated
> idempotency key, `(attestation_id, K)`: a retry re-presents the same `attestation_id` and proves
> possession of the same `K`, which replays the committed enrollment. (`operationId` remains an
> internal cross-table recovery id only. The `pending`/`committed` claim lifecycle this round
> described was separately removed by the SQL-only single-transaction change, Q18.)

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

**Change (§11.2, §11.3, appendix).** The outcome became an explicit wire contract: an
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
`OutcomeRecordSchemaFixtureTest` adds a canonical fixture for each (operation × outcome) cell, shared
with Lock's conformance suite.

> **Superseded by Q21.** This round's "`credential_fingerprint` present iff `committed`" rule was
> too coarse — it contradicted two already-defined success shapes (a committed bare-key appraisal has
> no credential, and a committed `EXECUTION_STARTED` bootstrap provisions none). Q21 replaced it with
> an **event kind × operation subtype × outcome** matrix and renamed the field `operation_outcome`.

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

The title "Ledger drops LDAP and Couchbase" describes the **Lock** side. It is **not** what
establishes the issuer-side `Commit` atomicity: the entity + `IssuanceLog` + outbox writes happen in
**jans-auth-server**, before delivery to Lock, so they need their own transaction-domain requirement
— stated as Q20.

## Q19. The ID-JAG two-server correction had not propagated through all documents

**Status: resolved** — every passage now reflects the two-AS model and the artifacts each server
actually holds.

**Raised.** The revised §5 diagram correctly shows the **Resource AS (jans)** opening the execution
when it **redeems** the ID-JAG, while the ID-JAG is **issued** by a separate **IdP AS** across a
trust boundary. Several other passages still assumed the earlier single-authority model: §3's
renewal paragraph implied the execution pair comes from the ID-JAG; §10.9 described jans as *gating
ID-JAG issuance* rather than distinguishing issuer-side login policy from redemption-side acceptance;
§11.2's bootstrap fingerprinted the original ID token, which need not reach jans; PR 5 said it adds
`txn` to the ID-JAG; and `IdJagServiceTest` minted execution identifiers and tested issuer-side
behaviour without separating the roles. Separately, an external IdP's authentication/FIDO events
cannot be resolved against local Jans FIDO records.

**Change (§§3, 5, 10.9, 11.2, appendix).** Added an explicit **"artifacts available at each server"**
table to §5 (the IdP AS holds the ID token / login / FIDO records and issues the ID-JAG; jans, as
the Resource AS, sees only the ID-JAG it redeems plus the key material at `/token`, and **mints** the
`(trace_execution_id, execution_authority)` pair there — the ID-JAG carries no execution id), and
aligned every passage to it:

- **§3 renewal:** the execution id on a renewal is the pair **jans minted and returned** on the
  opening call (echoed as the prior SVID's claim / `txn`), explicitly **not** carried by the ID-JAG.
- **§10.9:** split human assurance into an **issuer-side login bar** (`idJagRequirePhishingResistant`,
  applied only when this jans is the IdP AS) and a **redemption-side acceptance check** at `/token`
  that maps the ID-JAG's *asserted* `acr`/`amr` to a server level and refuses an insufficient
  delegation before issuing. jans records the asserted values; it does not re-derive them.
- **§11.2:** the `EXECUTION_STARTED` bootstrap fingerprints the **ID-JAG jans redeemed**, not the
  human's ID token (which it does not hold unless it is the IdP); the diagram node says "ID-JAG
  **redeemed**."
- **External-IdP `sid`:** a `sid` from an external IdP resolves to **no** local FIDO record; it is an
  opaque issuer-scoped reference whose ceremony evidence lives at that IdP (a cross-producer link),
  recorded in §3, §10.9, §11.2, and the glossary.
- **Appendix:** PR 5 now describes **redeeming** the ID-JAG and minting the pair into the registry /
  SVID (not stamping `txn` into the ID-JAG); `IdJagServiceTest`/`IdJagRedemptionTest` separate the
  issuer side (jans-as-IdP login gate, skipped for external IdPs) from the redemption side
  (validation, acceptance check, pair minting, external-IdP `sid` non-resolution).

## Q20. The one-transaction `Commit` needs an explicit issuer-side transaction boundary

**Status: resolved** — §11.3 states the requirement, names the database and transaction API, and
answers the deployment question; §9.5 and the appendix are aligned.

**Raised.** The protocol depends on the issuer's entity (`TokenEntity` / `Client`+`KeyEnrollment` /
`AttestationAssessment`+`KeyAttestationState`), the `IssuanceLog`, and the outbox state committing in
**one** database transaction. Q18 justified this under "SQL-only," but that framing is about *Lock*,
whose ingestion is asynchronous and downstream. Making Lock SQL-only does not establish the
**issuer-side** transaction boundary — the relevant writes are in jans-auth-server. The design had
not stated that boundary as a requirement, named the database/API, or said whether the feature
restricts Jans deployments.

**Change (§11.3, §9.5, appendix).** Added an explicit **issuer-side transaction-boundary
requirement**: hardware-anchored issuance requires the participating jans-auth-server entities and
the local evidence tables (`jansTraceOutbox`, `jansIssuanceLog`, `jansTraceIntake`,
`jansTraceChainLease`) to reside in **one supported SQL transaction domain** — the same `jans-orm`
SQL database, one datasource — so a single **native local (non-XA) transaction** spans all of them;
Lock ingestion stays asynchronous and outside it. Named the support: the **`jans-orm` SQL
persistence layer** (`PersistenceEntryManager`, SQL backend) on **MySQL 8+** or **PostgreSQL**, local
`BEGIN … COMMIT` on one connection, clustered DB allowed. Answered the deployment question: **this
feature** requires the SQL backend for the issuing node and **fails closed at startup** otherwise;
it does **not** globally restrict Jans and introduces **no separate persistence path** (the evidence
tables are ordinary SQL entities in the same schema, not a second datastore). §9.5's enrollment
transaction and the appendix schema/fault-test rows now reference this boundary.

## Q21. The outcome schema contradicted the success event definitions

**Status: resolved** — the required identifying artifact is now defined by event kind × operation
subtype × outcome (§11.2 matrix); the field is renamed `operation_outcome`.

**Raised.** Q17's invariant required `credential_fingerprint` on *every* `committed` record, but two
success shapes already defined in §11.2 have no credential fingerprint: a **bare-key appraisal**
(`CREDENTIAL_PROVISIONED` with no credential bound, identified by `attestation_id` + assessed-key
`jkt`) and a successful **`EXECUTION_STARTED`** (which carries its source grant in `tokens[]` and
provisions no credential). Valid success records therefore failed the proposed invariant. Separately,
`provisioning_outcome` was a misnomer on `EXECUTION_STARTED`, which starts an execution rather than
provisioning anything.

**Change (§11.2, §11.3, appendix).** Replaced the single "committed ⇒ fingerprint" rule with a
matrix keyed by **event kind × operation subtype × outcome**, each committed success carrying the
identifying artifact proper to its operation:

| Successful operation | Required identifying artifact |
|----------------------|-------------------------------|
| SVID issuance | `credential_fingerprint` (SVID `jti`/`cnf_key_thumbprint`) |
| Key enrollment | enrolled-key thumbprint (`jkt`) |
| Bare-key appraisal | `attestation_id` + assessed-key thumbprint (`jkt`) — **no** `credential_fingerprint` |
| Execution bootstrap | execution pair (`trace_execution_id` + `execution_authority`) + source-grant reference — **no** `credential_fingerprint` |

`credential_fingerprint` is now required **only** for committed SVID issuance and key enrollment, and
MUST be absent for a bare-key appraisal, an `EXECUTION_STARTED` bootstrap, and every `aborted` record.
The field is renamed **`operation_outcome`** (it applies to `EXECUTION_STARTED` too). The same matrix
drives `OutcomeRecordSchemaFixtureTest` (a fixture per subtype × outcome, asserting the artifact rule
both ways) and the Lock-compatibility confirmation (a schema that requires `credential_fingerprint`
uniformly on `CREDENTIAL_PROVISIONED` is itself the contradiction, resolved Lock-side).

## Q22. Appraisal persistence had two incompatible commit models

**Status: resolved** — §9.3c and §11.3 now describe one appraisal commit protocol.

**Raised.** §9.3c wrote the assessment, the `completed` challenge, and the authoritative
`KeyAttestationState` overwrite as **separately recoverable, generation-guarded** operations, while
§11.3's **Commit** bound the entity, the state write-through, the `IssuanceLog`, and the outbox
transition into **one** transaction. The two models left different failure windows: under §9.3c a
crash between the assessment write and the state overwrite could leave a **negative** assessment
durable while issuance kept reading the **old positive** `KeyAttestationState`.

**Change (§9.3c, §10.4, §11.3, appendix).** Chose one protocol — the §11.3 **Commit** model applied
to appraisal. The slow **verifier call stays outside any transaction** (it is network I/O); then a
**single SQL transaction in the issuer-side transaction domain** (a) re-reads and validates the
challenge under `SELECT … FOR UPDATE`, confirming it is still `processing` under this worker's
`leaseEpoch` (the fence, re-checked inside the transaction), (b) inserts the immutable
`AttestationAssessment`, (c) applies the `KeyAttestationState` write-through — only for a
`supersedesEligible` verdict whose `appraisalGeneration` is strictly newer (the §10.4 guard,
evaluated in-transaction under `revision`), (d) transitions the challenge to `completed`, and
(e) stages the §11.3 evidence commitment — **all-or-nothing**. A negative verdict's assessment and
its state overwrite are now the *same* commit, so the flagged window is gone.

Two cases are stated explicitly: **superseded generation** — a verdict whose generation is older at
commit is recorded as evidence but **skips** the write-through (never regresses the row);
**outage (`none`)** — a verifier-unreachable result is recorded as evidence, is **never** written
through to state (neither grants nor revokes authority), keeps the challenge `processing → pending`
for resubmission up to the retry limit, and returns `503 verifier_unavailable`. Recovery is
resubmission: a crash before commit leaves nothing durable (lease repaired to `pending`, re-run
under a new `leaseEpoch`); a crash after commit is a no-op re-submission (`challenge_used`). This
also settles the algorithm that Q13's "fenced verifier worker" item had left open.

## Q23. Key rotation assigned two proofs to one header and hard-coded POST

**Status: resolved** — §9.5 defines a concrete RFC 7592 wire format for the key change, distinct from
the first-enrollment `/register` flow.

**Raised.** The key-replacement rule (Q15) said the update carries both a **new-key** proof and an
**old-key** authorization "in different request locations," but both were specified as **DPoP** — and
there is only one `DPoP` header, so the locations were never actually defined. Two further defects:
the rule used `htm=POST`, but an RFC 7592 registration update is an **HTTP `PUT`** to the client
configuration endpoint; and it conflated *authenticating the updater* with *signing the mutation* —
a DPoP proof does not cover the request body (RFC 9449) and a `private_key_jwt` assertion is not a
signature over the key-change payload (RFC 7523), so neither proof, as specified, attested *which*
key was being added or removed.

**Change (§9.5, §9.9, appendix).** Defined a concrete three-part wire format for the `updateClient`
key change, an **RFC 7592 `PUT`** (`htm=PUT`, not `POST`):

- **(a) Authenticate the updater (old key)** — normal registration-management authentication: the
  registration access token's DPoP proof (`htm=PUT`, `htu`=client-config endpoint, `ath`) signed by
  a currently-trusted key, or a `private_key_jwt` assertion signed by the old key. This occupies the
  single `DPoP` header / client-assertion slot.
- **(b) Prove possession of the new key** — a **separately named body member `attested_key_pop`** (a
  `typ:attested-key-pop+jwt` signed by `K_new`), **not** a second `DPoP` header, so the two proofs no
  longer compete for one location.
- **(c) Sign the exact mutation** — because neither (a) nor (b)'s transport signs the body, both
  carry a `change_digest` over a canonical `key_change_request = { op, target_jkt, prior_jwks_digest }`;
  the server recomputes the digest over the received body and rejects a mismatch
  (`key_change_not_signed`). A `remove` needs (a)+(c) only.

§9.9's dual-key rollover steps and the `RegisterValidatorTest` row were aligned to this wire format
(including a test that `htm=PUT` is required and that a valid authentication with a `change_digest`
naming a different `target_jkt` than the body is refused).

## Q24. Enrollment retry idempotency had no client-visible key

**Status: resolved** — the idempotency key is the client-held `(attestation_id, K)`, with request
binding, retention, and replay behaviour defined (§9.5).

**Raised.** Q15 made an enrollment retry idempotent "because the claim carries the `operationId`" —
a retry would "find the claim already present with its own `operationId`." But `operationId` is a
**server-internal fresh UUID** the client never sees; after a lost `/register` response the caller
has no way to present its original `operationId`, and a fresh registration would allocate a new one.
A stored `operationId` makes server-internal cross-table recovery idempotent but does **not** make
an HTTP retry idempotent.

**Change (§9.5, appendix).** Defined a **client-visible, authenticated idempotency key**: the
**`attestation_id`** the client already received from `/attestation`, bound to **possession of `K`**.

- **Authentication / request binding.** The retry re-presents the same `attestation_id`, resolves to
  the same `client_id`, and carries the **DPoP proof over `K`** the enrollment already requires; the
  `KeyEnrollmentClaim` records the `claimedJkt` it was first enrolled under, and the idempotent path
  is taken only when the presented proof key equals `claimedJkt`. So a party that merely learned an
  `attestation_id` cannot drive it — the idempotency binding reuses the existing key-possession
  proof, no new secret.
- **Replay behaviour.** Same `attestation_id` + same `client_id` + proof key == `claimedJkt` →
  **replay** the committed enrollment result without re-running the transaction; same
  `attestation_id` but a different `client_id` (or wrong key) → `assessment_already_enrolled`; no
  claim (crash before commit) → re-run fresh.
- **Retention.** The `KeyEnrollmentClaim` persists for the life of the enrollment, so the
  replay answer outlives any plausible retry — there is no short idempotency-key TTL to miss.

An optional client-chosen `Idempotency-Key` header MAY be stored on the claim and must agree with the
`(attestation_id, client_id, K)` binding; v1 relies on `(attestation_id, K)` alone. The internal
`operationId` is retained only as a cross-table recovery-matching id, never the client's key.

## Q25. "Re-finalizing produces byte-identical bytes" was unqualified

**Status: resolved** — §11.3 freezes the signing input and installs the final bytes once; retries
adopt the stored winner.

**Raised.** The §11.3 **Finalize-and-sign** transition claimed re-finalizing a resolved entry
produces byte-identical bytes "idempotent and deterministic." But Ed25519 signature determinism does
not make a *rebuild* reproduce the bytes: rebuilding after a crash can pick a fresh `signed_at`, a
different signing `kid` (after a key rotation), or other generated fields, so the input — not just
the signing function — must be pinned. The useful guarantee is **one authoritative byte sequence**,
not one execution of the signer.

**Change (§11.3, appendix).** **Finalize-and-sign** now **freezes the complete signing input the
first time it runs** — the canonical record plus every otherwise-generated field (`signed_at`, the
selected signing `kid`, any nonce) — persists that frozen input on the entry, and **installs the
signed bytes once via a set-if-unset CAS** (`signed_bytes`). A concurrent finalizer or a post-crash
retry that loses the CAS **adopts the stored winner's bytes** and does not re-sign; a re-finalize
that still needs to run re-reads the frozen input, so `signed_at`/`kid` cannot drift. The outbox
schema stores the frozen input alongside the installed bytes, and `TraceRecordBuilderTest` asserts
no drift across a rebuild (fresh clock / rotated `kid`) and that concurrent finalizers converge on
one byte sequence with the loser adopting it. The decision log and the §11.3 `TraceRecordBuilder`
note were corrected from "signing is deterministic, so bytes are reused" to this freeze-and-install
rule.

## Later review rounds

Subsequent review rounds refined the above into the current design; the material changes are already
folded into the numbered sections of the main document (notably the §9.3c appraisal single-transaction
commit (verifier call outside the transaction, then assessment + state write-through + `completed` +
evidence commit atomically; Q22, which unified §9.3c with §11.3 and closed the negative-verdict
window), the §9.5 enrollment transaction, the §9.7/§10.4 single-row state model with `revision` +
`appraisalGeneration`, the §11.3 append/commit protocol, the §9.3a Azure AK-binding gap and
three-valued `key_binding_strength`, the §10.5/§8 JWT-SVID algorithm allowlist, the §10.6/§10.8
delegation-expiry clamp and tenant-scoped principal binding, the §10.9 BE/BS-vs-hardware
distinction, the §10.10 token-privacy scope, the §11.3 sign-once-at-resolution rule, the §11.2/§11.3
per-producer outcome wire contract (`provisioning_outcome`, bootstrap aborts as `EXECUTION_STARTED`),
the SQL-only backend reduction (§§9.5/11.3, which removed the `indeterminate` outcome and the
LDAP/Couchbase portability caveats), the §5 two-authorization-server model (IdP AS issues the
ID-JAG, Resource AS redeems it and mints the execution pair; Q19), the §11.3 issuer-side
transaction-boundary requirement (entity + evidence tables in one `jans-orm` SQL transaction domain,
MySQL/PostgreSQL, Lock ingestion outside it; Q20), the §11.2 outcome schema keyed by event kind ×
operation subtype × outcome with the field renamed `operation_outcome` (Q21, which corrected Q17's
too-coarse "committed ⇒ fingerprint" rule), the §9.3c/§11.3 unified appraisal commit (Q22), the
§9.5 key-replacement RFC 7592 `PUT` wire format (old-key auth in the `DPoP` header, new-key
`attested_key_pop` body member, `change_digest` signing the mutation; Q23, which corrected the
two-proofs-one-header / hard-coded-`POST` defects), the §9.5 enrollment-retry idempotency key
`(attestation_id, K)` (Q24, which replaced the client-invisible `operationId` retry rule), the
§11.3 freeze-signing-input + install-once-CAS rule (Q25, which qualified "re-finalizing is
byte-identical" into one authoritative byte sequence, not one signer execution), and the
§16.1 key-revocation delay). This history preserves the original questions that drove them; for
current behaviour, read the main document.
