# Hardware-Anchored Identity — Review History

This document records review questions raised against
[`hardware-anchored-identity.md`](./hardware-anchored-identity.md) and the change each one
produced. It is a history, not a specification: the authoritative behaviour is in the main design
document's numbered sections, which these entries point to. Keep new review rounds here so the main
document stays a clean specification rather than a running changelog.

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
- **Reconciliation on the entity, not token absence.** A later review round found that treating a
  separate marker's *absence* as proof of non-commit introduced a new crash gap (entity committed,
  marker not yet written → evidence wrongly voided). The current design (§11.3) makes the `staged`
  outbox entry a **three-valued** operation journal (committed / not-committed / unresolved) and
  resolves it by probing the **authoritative entity** the record names, binding the entity write
  and the commit flip in one native transaction on SQL/Couchbase. A missing marker means
  *unresolved* (retry), never *nothing happened*; retention covers unresolved operations and
  downtime.
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

**Raised.** A pre-enrollment attestation has no `client_id` and requires no DPoP, so it is
`supersedesEligible=false`; but only a `supersedesEligible=true` assessment could populate
`KeyAttestationState`, and issuance requires that state — so a freshly enrolled client could never
issue. Separately, DCR said to set `clientId` on the assessment while §9.7 said assessments are
immutable (a direct contradiction).

**Change (§§9.5, 9.7, 10.4).** Enrollment is now an explicit, idempotent **enrollment transaction**:
(1) verify the `/register` DPoP proof against the assessed key; (2) leave the assessment
**immutable** — no `clientId` back-fill; (3) create a separate **`KeyEnrollment`** binding
`(clientId, jkt) → attestationId`; (4) **initialize** `KeyAttestationState(clientId, jkt)` at
`revision = 0`, authorized by the DCR proof rather than by `supersedesEligible`; (5) record the
client attribute and emit the enrollment TRACE record. `supersedesEligible` now governs only
*overwriting* an existing client's state, not *initializing* a key's first state; the write-side CAS
table gained a distinct enrollment-initialization row. One assessment enrolls exactly one client
(`assessment_already_enrolled` otherwise), and adding a replacement key reuses the same transaction.

## Q11. Attestation ordering needs rules beyond CAS

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

## Later review rounds

Subsequent review rounds refined the above into the current design; the material changes are already
folded into the numbered sections of the main document (notably the §9.3c fenced verifier worker,
the §9.5 enrollment transaction, the §9.7/§10.4 single-row state model with `revision` +
`appraisalGeneration`, the §11.3 append/commit protocol, the §9.3a Azure AK-binding gap and
three-valued `key_binding_strength`, the §10.5/§8 JWT-SVID algorithm allowlist, the §10.6/§10.8
delegation-expiry clamp and tenant-scoped principal binding, the §10.9 BE/BS-vs-hardware
distinction, the §10.10 token-privacy scope, and the §16.1 key-revocation delay). This history
preserves the original questions that drove them; for current behaviour, read the main document.
