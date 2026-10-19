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

- **Append protocol.** Each `(producer_id, chain_id)` is one serial chain per node; a unique index
  on `(producer_id, chain_id, sequence_number)` makes a position un-double-writable; a per-chain
  tail pointer carrying `{ next_sequence, tail_record_hash, epoch }` is advanced by CAS with the
  outbox unique-insert as the authority; `epoch` fences a stale thread after an operator repair;
  lost-CAS / lost-insert retry up to `traceOutboxAppendMaxRetries`.
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

## Later review rounds

Subsequent review rounds refined the above into the current design; the material changes are already
folded into the numbered sections of the main document (notably the §9.7/§10.4 single-row state
model, the §11.3 append/commit protocol, the §9.3a Azure AK-binding gap, the §10.8–§10.9
execution-binding and human-assurance rules, and the §16.1 key-revocation delay). This history
preserves the original questions that drove them; for current behaviour, read the main document.
