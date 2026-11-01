# Gluu Ledger Product Requirements Document

Version 0.1 • Proposed product scope • November 1 2026

Audience: Gluu product, engineering, security, and go to market teams

## 1 Product decision

Gluu Ledger is an enterprise evidence and assurance product built on Janssen Lock Server. It collects signed evidence from identity systems, policy decision points, enforcement points, and target systems; reconstructs governed executions; and explains what the evidence establishes, what remains unknown, and which controls need attention.

The recommended first commercial release combines capability evidence with human authentication, FIDO ceremony evidence, and a supported hardware-backed workload assurance path. The existing TRACE engineering MVP is an internal foundation milestone. It is insufficient on its own for the proposed commercial promise.

The product answers five questions: Who authorized it? Which workload acted? Which key and runtime were involved? What did policy allow? What effect was observed? Answers must identify their sources, applicable assessment profile, verification time, and remaining trust assumptions.

This PRD proposes requirements and release gates. It does not claim that the designs are implemented. Hardware enrollment, product UI, operational service levels, and several correlation refinements are proposed additions to the supplied designs. No release date, pricing, or staffing commitment is implied.

## 2 Problem and intended outcomes

Enterprises can have authentication events, authorization decisions, gateway records, and application telemetry without a reliable connection among them. An investigator cannot readily establish whether a human delegated a particular action, which workload credential was used, whether the enforcement point applied the decision to the same request, or whether the target produced the reported effect. Governors lack a consistent account of evidence coverage, control weaknesses, ownership, and accepted risk.

Gluu Ledger must reduce the effort required to assemble and verify that account. It must make missing evidence and contradictory claims visible while preserving the original assertions. Its value depends on credible correlation and bounded assurance, rather than simply collecting more records.

The first deployments should focus on a small set of high-risk capabilities in agent gateways, internal services, or business applications. Examples include releasing a payment hold, changing privileged access, or exporting sensitive data. These are proposed pilot scenarios, not evidence of customer demand.

## 3 Customers and users

| User | Job | Product outcome |
|---|---|---|
| Security architect and platform owner | Instrument applications and specify evidence requirements | Repeatable integration with explicit trust boundaries |
| Investigator and incident responder | Reconstruct a disputed operation | Searchable execution view with sources and gaps |
| Auditor and assurance reviewer | Independently assess an evidence set | Reproducible assessments and portable verification |
| Capability owner | Understand use and control deficiencies | Capability-level findings with ownership and history |
| Board member or executive | Set risk priorities and investment | A drillable governance heat map with disclosed coverage |
| Ledger operator | Run the service safely | Isolation, predictable retention, recoverability, and capacity controls |

Proposed economic buyers are enterprise security and platform leaders. Validate buyer ownership, procurement needs, and willingness to pay through design partners before final packaging.

## 4 Product boundaries

Gluu Ledger provides evidence collection, verification, correlation, assessment, investigation, and governance reporting. Janssen Lock Server supplies the underlying evidence service. Gluu productizes supported deployment, integrations, management, user experience, operational assurance, and support. This is a proposed packaging boundary; it does not prescribe which upstream features become commercial-only.

Cedarling remains a PDP. PEPs and target systems remain responsible for enforcing business authorization and observing effects. Jans Auth Server owns authentication sessions and token issuance. Jans FIDO Server verifies authenticator ceremonies. An attestation verifier appraises platform evidence. Ledger consumes their evidence without taking over those responsibilities.

Ledger must support third-party producers and PDPs through documented profiles. Janssen and Cedarling are first-party integrations, not prerequisites for every deployment. Humanless workloads remain first-class; absence of a human session is not inherently a governance failure.

Initial non-goals are a general workflow orchestrator, a replacement for SIEM or GRC, autonomous remediation, universal remote-attestation verification, custody of customer bearer tokens, and a blockchain consensus network. APP process governance is an optional later binding. Formal policy proofs are optional evidence artifacts; a Ledger signature or a deterministic PDP is not such a proof.

## 5 Core customer journeys

### Govern one capability

An administrator registers the PDP, gateway, and target observer, binds each to the correct evidence domain, and authorizes its permitted claims. A capability owner publishes a versioned mapping and chooses expected evidence. The application propagates an execution identity. Ledger displays the decision, invocation, and effect together, with request binding and coverage findings where available.

### Investigate a human delegated action

An investigator starts with an invocation, execution ID, or token reference. Ledger links the workload and delegation to an Auth Server authentication event and the exact FIDO ceremony when that relationship is evidenced. The investigator can distinguish authenticated session, human confirmation, authorization grant, and workload action. A session association alone does not establish approval of the exact action.

### Verify a hardware backed workload

A platform operator enrolls a workload instance and its public key under an administrative policy. A supported verifier supplies a fresh attestation result. Ledger evaluates the relationship among the attested runtime, key, authenticated workload, and relevant record or request. The execution view discloses whether the result applies to the actor, evidence producer, or both, and whether proof of possession covered the actual request.

### Assess governance risk

A capability owner or governor reviews findings grouped by business unit, risk, owner, and region. Each heat-map cell exposes its policy, evidence coverage, freshness, unknowns, and accepted-risk references. Reviewers can drill into an underlying execution without treating a green status as proof that all real-world activity was observed.

### Supply evidence to an auditor

An authorized reviewer exports an Evidence Packet for a scoped investigation. The verifier checks original records, key authorization, assessment signatures, profile versions, checkpoints, and any included anchor proofs without accessing the running service. Missing dependencies reduce the verdict rather than being silently accepted.

## 6 Functional requirements

Priority notation: P0 is required for the proposed first commercial release; P1 follows that release; P2 is optional expansion. P0 requirements can be implemented across several internal milestones.

### Evidence collection and integrity

**EV01 P0 — Authenticated ingestion.** Provide versioned single and bulk submission APIs protected by TLS and OAuth. Derive the evidence domain from authenticated client configuration before producer-key resolution or content routing. Acceptance: an attacker cannot select another domain through body fields, identifiers, or correlation edges.

**EV02 P0 — Producer claim authorization.** Manage producer keys, permitted event kinds, measurement points, validity, rotation, and revocation through a separate administrative permission. Discovery of a public key and possession of that key do not authorize a claim. Acceptance: a valid PDP key cannot submit an authorized FIDO or PEP assertion merely by changing the event kind.

**EV03 P0 — Immutable assertions.** Preserve the submitted assertion and use the declared canonicalization for verification and digest computation. Store all Ledger-derived values separately. Acceptance: later enrichment, assessment, export, or key rotation does not change the original assertion or its content digest.

**EV04 P0 — Atomic and idempotent acceptance.** Commit the assertion, receipt, and required indexes atomically before acknowledging durable acceptance. Replaying identical content returns the original receipt; identity reuse with different content returns a conflict. Bulk results are per record; mixed-producer batches are rejected at the envelope level under the current contract.

**EV05 P0 — Visible integrity findings.** Detect producer-chain gaps, mismatched links, equivocation, and late arrival. Support out-of-order records without manufacturing global event order. Acceptance: a delayed predecessor can resolve a derived gap while prior assessments and signed assertions remain inspectable.

**EV06 P0 — Durable delivery integration.** Provide a supported emitter with bounded queues, retry/backoff, queue-age telemetry, and a persistent outbox option for the server-side first-party integrations. Declare crash loss and restart behavior. This extends the source MVP, which defers producer durability. Acceptance: a tested process crash and collector outage produce either successful replay or explicit loss/coverage disclosure; neither can silently appear complete.

### Cedarling and enforcement evidence

**CD01 P0 — Native decision producer.** Integrate TRACE production with Cedarling using the shared cryptographic core. Capture the actual returned decision, signed action/resource-type facts, PDP instance, policy-store identity/version, and reproducible policy-bundle commitment. Include DENY decisions for every configured captured capability. Support unsigned authorization inputs and multi-issuer token inputs without inventing token context.

**CD02 P0 — Preserve PDP behavior.** Perform signing and delivery outside the decision hot path. Missing execution context or collector unavailability must not change Cedarling's policy result. Return accurate diagnostics for emitted, queued, omitted, and failed evidence. A host or PEP may separately enforce an evidence-required policy. Resolve the source contradiction that describes a context-less record as both emitted and “not emitted.”

**CD03 P0 — Capture policy and performance disclosure.** Configure the captured action/resource pairs, record configuration changes, and expose coverage exclusions and sampling. Defaults must not silently exclude denials for captured pairs. Acceptance: an uncaptured event is never presented as proof that no event occurred. Benchmark TRACE overhead separately from policy evaluation; do not carry over a Cedarling decision-latency target as Ledger throughput.

**CD04 P0 — Enforcement and effect integration.** Deliver at least one supported gateway/PEP adapter and one target-observer example. The enforcement point signs invocation evidence using a producer authorization distinct from the PDP. Preserve the distinction among allowed, dispatched, successful invocation, confirmed effect, failure, and reversal. A confirmed effect requires a commitment to observed result bytes under the selected profile.

**CD05 P0 — Operation binding.** Compare declared request/tool-call/result commitments only under matching digest contexts. Acceptance: changed tool parameters between decision and invocation produce an explicit mismatch; missing or incomparable commitments remain unknown. Correlation IDs alone do not establish request equivalence.

### Human authentication and FIDO

**HF01 P0 — Auth Server evidence.** Capture authentication resolution, outcome, achieved authentication method and ACR/AMR when available, and issuer-scoped session identity. Emit asynchronously using a dedicated TRACE producer key. Preserve session evidence that predates an execution and attach later correlations with separate provenance. Failed-authentication capture policy and limits must be disclosed.

**HF02 P0 — FIDO ceremony evidence.** Capture registration and assertion ceremony results, including server-observed success, rejection, and abandonment, with credential references protected appropriately. Include relevant attestation/MDS appraisal provenance, authenticator metadata, and user-presence/user-verification results when verified and available. These additional assurance fields require a pinned producer schema. Never infer an on-device biometric failure that the server did not observe.

**HF03 P0 — Precise authentication linkage.** Where the integration provides it, explicitly link the Auth Server authentication resolution to its consumed FIDO ceremony rather than relying only on a shared session. Carry scoped ceremony or flow identifiers for pre-session events. This requires a documented schema extension to the current mandatory-session design; do not fabricate a session or lose a valid registration simply because a session is absent.

**HF04 P0 — Honest authenticator assurance.** Distinguish credential possession, user verification, attestation appraisal, backup eligibility/state when available, and evidence about key protection. Do not label every passkey, platform authenticator, or cross-platform authenticator as a device-bound hardware key. Unknown and unsupported classifications remain explicit. Acceptance: a ceremony with no usable attestation cannot gain hardware-protection assurance from its attachment value alone.

**HF05 P0 — Human authority boundary.** Distinguish authentication, local confirmation, delegated authority, and action-specific approval. An authorization approval references the grant, transaction, or authoritative decision it produced and the operation it covers. A FIDO assertion or session join alone must not produce the claim “this human authorized this exact action.”

### Hardware anchored identity and key assurance

**HW01 P0 — Policy controlled enrollment.** Support one documented workload enrollment path binding stable workload identity, instance identity, public-key thumbprint, administrative authority, and verifier appraisal. Preserve enrollment, renewal, rotation, and revocation evidence. SSA/DCR may establish fleet enrollment authority but cannot establish hardware protection or attestation by itself. Enrollment must not let a workload assign its own trust class or claim scope.

**HW02 P0 — Supported protected-key path.** Deliver at least one named and tested hardware-backed workload key integration and one protected Ledger assessment/checkpoint signing integration; they may use different technologies. Keep private keys behind signer/provider interfaces. The supported matrix must identify key algorithms, key non-exportability evidence, runtime-binding guarantees, and throughput limits. Software keys remain supported with explicitly lower assurance.

**HW03 P0 — Algorithm feasibility gate.** Resolve the Ed25519-only TRACE profile against the actual hardware/provider algorithms before committing the launch support matrix. The workload authentication key need not be the producer TRACE signing key. If protected TRACE signing needs another algorithm, introduce an explicitly versioned accepted profile and conformance vectors; never silently switch algorithms or substitute a software key while retaining a hardware-backed claim.

**HW04 P0 — Attestation appraisal provenance.** Consume signed results from at least one configured verifier; preserve artifact digest, attester, verifier, appraisal time, freshness, reference values, endorsement references, and appraisal outcome. Ledger validates the verifier's authority and applicable policy. Unsupported raw attestation evidence can be preserved but cannot receive a successful appraisal solely because it was supplied.

**HW05 P0 — Separate actor and producer binding.** Evaluate the actor instance/key relationship separately from the evidence producer instance/key relationship. A Cedarling record describes an agent but is signed by the PDP; these commonly occupy different runtimes. Only demand identity equality for a declared co-resident profile. Acceptance: the product neither rejects legitimate remote-PDP evidence for unequal identities nor lends the PDP's attestation to the agent. This corrects an ambiguity in the full design's four-way instance-binding model.

**HW06 P0 — Request possession and freshness.** Preserve relevant credential confirmation-key references and validated proof-of-possession facts for at least one supported mechanism. Bind the proof to request context, audience, freshness, and replay controls as required by that mechanism. DPoP-style request binding is not a body commitment by itself; use operation commitments for parameters it does not cover. Distinguish verified authentication proof from a producer's assertion that a proof existed.

**HW07 P0 — No implicit hardware assurance.** A SPIFFE/WIMSE identifier, fleet SSA, registered public key, fresh token, or valid signature alone cannot establish hardware custody. A shared fleet signing key cannot uniquely bind a record to one pod. Acceptance: a fleet-key deployment remains usable, but instance assurance stays indeterminate until independent instance-binding evidence satisfies the profile.

**HW08 P1 — Posture lifecycle and responses.** Add credential-provisioning evidence and security-signal/remediation correlation. Show when a posture or compromise signal was received, what external component restricted access, and the delay. Ledger reports the relationship; revocation and enforcement remain responsibilities of the issuer and PEP.

### Correlation and assurance

**AS01 P0 — Execution graph.** Correlate issuer-scoped token references, execution authority/ID, producer identity, workload, operation, human session, and causal parents. Expose asserted versus collector-derived edges and their provenance. Store pre-execution authentication evidence without fabricating an execution identity. Restrict graph traversal to the authenticated domain; imported evidence requires explicit provenance and authorization.

**AS02 P0 — Settlement and receipts.** Expose admission separately from the per-record submitted/settled lifecycle and execution completeness. Produce signed settlement assessments and receipt checkpoints with dedicated authorized keys. Acceptance: a settled decision does not assert that an invocation occurred, and a receipt checkpoint does not assert that the producer supplied its full history.

**AS03 P0 — Versioned assessments.** Use valid, invalid, indeterminate, and not evaluated for per-check results. Every assessment includes source references, profile identity/hash, evaluation time, and supersession where applicable. A required indeterminate check blocks the stronger claim. Historical findings remain immutable; current reappraisal may warn about later compromise without rewriting prior admission.

**AS04 P0 — Completeness expectations.** Define capability-specific required producers, record relationships, bindings, and observation deadlines. Evaluate late evidence through new assessments. Missing evidence means expected evidence missing, not proven non-occurrence. A completeness verdict is always scoped to the profile, covered population, and evaluation time.

**AS05 P0 — Capability meaning.** Resolve capability IDs from signed action/resource-type facts through a versioned authoritative mapping. Preserve per-decision/per-invocation results for batches. Use historical policy context, causal linkage, and mapping provenance when a PEP lacks policy-store metadata; unresolved ambiguity remains explicit. Never ask a PEP to invent a business capability label.

**AS06 P1 — Delegation and authority transitions.** Evaluate supported non-expansion constraints and reconstruct authority changes from signed evidence. Pin supported comparison semantics; unsupported constraints remain indeterminate. Include token-exchange origin and source/derived token lineage without retaining bearer credentials.

**AS07 P1 — Portable independent verification.** Export original records, signed assessments, producer-key authorization statements, applicable mappings, manifests, checkpoints, and necessary proofs in an Evidence Packet. Ship an offline verifier. Its verdict states included evidence, trust roots, missing material, and revocation-check limitations. Selective disclosure must not modify signed assertions or claim undisclosed checks passed.

**AS08 P1 — External anchoring.** Support a named external transparency or witness integration with pinned proof semantics. Display pending, anchored, unverifiable, and failed states. An anchor commits to included bytes; it does not make the producer honest or reveal omitted activity. Independent-assurance claims require a stated trust model beyond Ledger's own signature.

### Investigation and governance experience

**UX01 P0 — Execution view.** Provide a graph and accessible tabular view of authority, authentication, actor and producer identities, keys, policy decision, enforcement, and observed effect. Make unknowns and contradictory evidence prominent. Display producer time, receipt time, and assessment time separately. Arrival order must not be presented as causal order.

**UX02 P0 — Search and drill down.** Search by scoped execution, capability, workload, producer, session, token reference, transaction, outcome, time, and integrity finding. Support stable pagination and filtered export. Restrict sensitive references and payloads by role and domain.

**UX03 P0 — Explain each result.** A reviewer can inspect why a check passed or failed, what evidence supports it, and what would resolve an indeterminate result. The interface must distinguish producer assertion, observer assertion, Ledger verification, and optional external verification. Trust tiers are summaries; dimension-level results remain available.

**UX04 P0 — Governance reporting.** Report capability usage, evidence completeness, unknown attribution, unmapped capability use, required-authentication shortfalls, and operation-binding findings. Keep authorization, invocation, and effect denominators separate. Count individual entries in batched records, deduplicate replay, and disclose capture exclusions and observation windows.

**UX05 P0 — Heat map with accountable interpretation.** Provide an initial heat map across Identity, Observability, Access, and Governance using configured indicators and thresholds. Each cell identifies owner, data coverage, freshness, assessment basis, and linked findings; insufficient evidence is visibly unknown. Annotations for risk acceptance carry approver, rationale, scope, and review/expiry date. Broader GRC workflow can remain external.

**UX06 P1 — Historical enrichment and integrations.** Resolve organization, capability owner/risk, and the distinct human/workload/enforcement/target region dimensions using effective versioned reference data. Preserve decision-time claims separately from later issuer lookups. Export findings to a supported SIEM/GRC destination; add OSCAL mapping only under a separately defined mapping contract.

## 7 Nonfunctional and operational requirements

The following are proposed launch targets to validate in a named reference environment, not measured properties of the current designs. Publish hardware/provider, record sizes, batch sizes, active domains, indexes, and test load with results.

| Area | Proposed target or release condition |
|---|---|
| Ingestion | Sustain 5,000 accepted records/second for one hour on a declared reference topology with 4 KiB median records and 100-record batches; report tails and scaling limits |
| Acceptance latency | p95 at or below 500 ms for a 100-record batch at the reference sustained load, including durable persistence; exclude and separately report client queue delay |
| Investigation | p95 at or below 2 seconds for the first 100 records of an indexed execution lookup against 10 million stored records in the reference environment |
| First-party producer behavior | Collector outage must not synchronously block authentication or authorization; publish p50/p95/p99 CPU and latency overhead with TRACE enabled |
| Backlog | Demonstrate a 30-minute collector outage and replay at the pilot peak rate within provisioned outbox capacity; disclose what happens at exhaustion |
| Durability | No acknowledged record loss under tested single-process/node failure; document quorum assumptions and storage failure boundaries |
| Availability | Proposed managed-service objective of 99.9 percent monthly API availability if a managed offering is launched; self-managed deployments receive a tested HA reference architecture |
| Recovery | Proposed DR target RPO at or below 5 minutes and RTO at or below 4 hours for regional disaster; distinguish this from acknowledged-write durability within the surviving storage topology |
| Isolation | Zero cross-domain disclosure in authorization, retrieval, traversal, exports, caches, and enrichment conformance tests |
| Security limits | Bound body size, batch count, nesting, strings, arrays, query cost, and traversal depth before expensive processing; make throttling and truncation explicit |
| Compatibility | Existing accepted assertions remain byte-verifiable across upgrades; profile and schema migrations are versioned and reversible where applicable |

At least one supported self-managed deployment is required at launch. Managed hosting is a packaging decision pending demand and operational readiness. Both modes need encryption at rest, documented key custody, backup/restore procedures, health metrics, capacity alerts, and support diagnostics that exclude secrets.

Lifecycle requirements include configurable retention by evidence class, lawful deletion handling, access-controlled sensitive artifacts, and auditable administrative actions. Receipt-ledger pruning must be checkpoint bounded and declared. Selective payload erasure needs its own disclosure and assurance rules; a retained hash is not automatically anonymous. Do not retain raw bearer tokens, private keys, or biometric templates in evidence.

Administrative and evidence-access auditing must avoid recursive TRACE generation. Use a separate scoped producer and a documented exclusion or independent management audit channel. Producer keys, OP token-signing keys, workload authentication keys, and Ledger assessment/checkpoint keys have separate purposes and authorization.

## 8 Delivery plan and release gates

| Milestone | Scope | Exit gate |
|---|---|---|
| Foundation | Shared crypto core, Lock ingestion, receipt chain, Cedarling/PEP evidence, integrity flags | Cross-language vectors, replay/conflict tests, atomicity, isolation, and baseline load tests pass |
| First commercial release | All P0 requirements, including capability resolution, authentication/FIDO correlation, settlement, completeness, UI, supported hardware path, and delivery resilience | End-to-end customer scenarios and supported hardware/provider matrix validated; claims match available assurance |
| Independent assurance release | P1 delegation, authority lifecycle, offline packets/verifier, external anchoring, richer enrichment | A verifier outside the running service reproduces scoped results and reports missing dependencies correctly |
| Optional expansion | APP process binding, broader attestation/provider matrix, advanced GovOps metrics and GRC mappings | Separate requirements, compatibility review, and conformance tests approved |

The first commercial release is deliberately broader than Phase 1 of the supplied implementation plan. If engineering capacity requires a smaller early release, present it as an evidence-collection preview and list absent FIDO/hardware/assurance capabilities explicitly. Do not market the preview as the complete product defined here.

## 9 End to end acceptance scenarios

1. **Human delegated protected action.** A human completes a supported FIDO flow; the Auth Server records achieved assurance and issues delegated authority. A supported workload uses a protected key and a fresh appraised instance. Cedarling evaluates the request, the gateway mediates it, and the target observer records a result. Ledger links the records and displays separate human, actor, producer, possession, operation-binding, and completeness results.
2. **Autonomous workload.** The same decision/invocation/effect path works with no human session. The applicable profile evaluates workload controls; the interface does not invent a sponsor or treat the missing human as an error when none is required.
3. **Substituted request.** The gateway executes changed parameters after an allow decision. Comparable commitments expose the mismatch even though the execution ID is identical.
4. **Borrowed attestation.** Runtime B submits evidence citing runtime A's appraisal. Ledger reports invalid or indeterminate binding according to available evidence and grants no instance-assurance uplift.
5. **Shared fleet key.** Two pods share a registered producer key. Both can submit authorized evidence, but the key alone cannot establish unique pod identity. Missing binding is visible in the execution view.
6. **Pre-session FIDO evidence.** A registration or discoverable-credential flow precedes session/execution creation. The agreed schema preserves its authentic identifier and later links it with provenance; no synthetic session or execution is created merely to satisfy ingestion.
7. **Outage and replay.** The collector is unavailable during load. Outboxes retain the supported backlog; replay produces one receipt per record and explicit delay/gap information. Overflow or process loss is disclosed.
8. **Compromised key.** A key is revoked after earlier accepted records. Historical admission remains visible. A current reappraisal reports compromise risk; untrusted producer timestamps cannot establish pre-compromise creation. Later submissions follow the pinned revocation policy.
9. **Missing target evidence.** Decision and invocation records settle individually, while the execution remains missing expected effect evidence after its observation deadline. Arrival of a valid effect creates a new completeness assessment.
10. **Domain attack.** A client guesses another domain's record, token, session, or execution ID and tries direct retrieval, traversal, and export. No foreign evidence or existence-sensitive content is disclosed.
11. **Offline review P1.** A packet verifies with configured trust roots and all required dependencies. Removing a key-authorization statement or anchor proof produces an explicitly reduced verdict, never an unexplained pass.

## 10 Success measures

Use design-partner baselines before setting commercial improvement commitments. Proposed validation goals are three pilot deployments, one production-like gateway integration per pilot, and a reproducible investigation of at least one high-risk capability in each.

| Measure | Definition |
|---|---|
| Time to first useful execution | Time from starting supported integration to a queryable decision plus invocation with capability meaning |
| Investigation effort | Reviewer time to assemble and verify a scoped execution compared with the pilot's existing approach |
| Expected evidence coverage | Eligible observed invocations satisfying the selected evidence profile divided by eligible observed invocations, with capture policy and window stated |
| Strong workload binding coverage | In-scope observed invocations with required actor key/instance/possession checks valid divided by in-scope observed invocations |
| Human authority coverage | Invocations requiring human authorization with evidenced operation-bound grant/delegation divided by observed invocations requiring that control |
| Attribution unknown rate | Observed invocations lacking sufficient actor/authority attribution divided by observed invocations |
| Mapping gap rate | Observed invocation entries with unresolved capability mapping divided by observed invocation entries |
| Delivery health | Queue age, rejection rate, replay rate, unresolved chain gaps, and disclosed drops or crash losses |
| Assurance reproducibility P1 | Packet assessments independently reproduced under the same declared inputs and trust policy divided by assessments tested |

These are measures over observed or externally enumerated populations. Estimating enterprise-wide coverage requires an independent inventory or target-side observation baseline. Ledger cannot infer unobserved activity solely from its own receipts.

## 11 Risks and product decisions

| Risk or conflict | Required decision or mitigation | Proposed accountable role |
|---|---|---|
| MVP defers capability mapping while GovOps profile requires it | Include resolution in commercial P0; reconcile engineering and standard conformance claims | Product and standards leads |
| FIDO and early authentication lack execution/session context | Pin scoped pre-session evidence schema and attribution semantics before adapter completion | Identity engineering lead |
| Ed25519 profile may not match selected hardware capabilities | Test provider/algorithm feasibility before naming supported platforms | Cryptography lead |
| Fleet keys undermine unique instance assurance | Offer per-instance enrollment or explicit lower assurance; never infer binding from fleet membership | Platform security lead |
| Full design conflates actor and producer runtime binding | Split the assessment dimensions and add remote-PDP negative/positive vectors | Architecture lead |
| Offline authenticity is marketed as producer truth | Keep claim boundaries, independent witness assumptions, and lineage coverage visible | Security and product leads |
| Current source wording overstates session-to-human authority | Require explicit delegation/action-approval evidence for stronger claims | Identity and authorization leads |
| Evidence volume exceeds delivery capacity | Benchmark signing, protected-key throughput, storage, indexing, retention, and replay together | Reliability lead |
| Privacy-sensitive identity and business correlation | Minimize payloads; scope identifiers; control access and retention; specify erasure behavior | Security and privacy owners |
| Product scope grows into orchestration or GRC | Keep process control and full compliance workflows external; use optional adapters | Product lead |

Pricing, managed-service regions, support tiers, exact launch provider, and commercial licensing boundaries remain open. Estimate cost from accepted bytes, retention, index footprint, signing/appraisal throughput, and assessment workload before selecting a charging unit. No prices are proposed in this PRD.

## 12 APP and standards compatibility

APP support is a P2 extension. Bind process authority, Frame version/digest, process instance, step occurrence, and source transactions to existing executions. Preserve APP conformance claims separately from Ledger verification. Add recovery, oversight, and independent-trace reconciliation through an optional profile. The APP orchestrator retains process control and PxER assembly. Business-entity inference remains an external service initially.

GovOps TRACE should remain vendor-neutral and PDP-neutral, with normative semantics owned by the standard rather than the Lock implementation. Product-specific views and service operations do not automatically become standard requirements. Publish explicit conformance scopes for producer, collector, receipt, assessment, hardware-binding, FIDO-binding, and optional APP behavior.

Pin implemented draft/profile versions and test vectors. Do not claim broad conformance to evolving SCITT, WIMSE, or APP drafts simply because their concepts appear in the design. Any additional signature algorithm or pre-session event schema requires explicit profile negotiation and compatibility tests.

## 13 Design review and source traceability

Sources are the user-supplied repository export `nynymike-lock-server-design-8a5edab282632443.txt`, the previously supplied full Lock design `design(3).md`, and `govops-trace-profile(6).md`. APP scope also draws on the previously supplied APP repository export and the preceding review. The new repository export lists the full `design.md` as a dependency but does not include it; the earlier supplied full design supplies that context. Source references below identify document names and headings within the supplied exports, not verified implementation state.

| Product area | Source basis | Principal PRD addition or correction |
|---|---|---|
| Ingestion and integrity | Lock Server TRACE MVP §§4–15; jans-trace-core MVP §§6–13 | Commercial delivery resilience and operating targets |
| Cedarling | Cedarling full design, Correlation, Operation binding, Deployment, Volume | Accurate diagnostics, coverage disclosure, hardware-aware fleet limits |
| Human authentication | Auth Server full design, Correlation, Bootstrap, Open questions | Explicit ceremony/authority linkage and pre-session handling |
| FIDO | FIDO full design, Event payload, Optional attestation, Open questions | Pin assurance fields, qualify hardware claims, preserve sessionless events |
| Hardware and runtime | Full Lock design, Attestation Binding, Deployment Instance Binding; core Signer abstraction | Supported enrollment/provider path, algorithm gate, split actor/producer binding |
| Settlement and completeness | Full Lock design, Versioned Assessments, Settlement, Completeness, Lineage | Commercial P0 scope and inspectable UI |
| Capability analytics | GovOps profile §§9, 13–14 | Resolve MVP conflict; batch-entry denominators; heat-map interpretation |
| Independent review | Full Lock design, Evidence Packets, External Anchoring, Receipt Ledger | Explicit P1 product/verifier acceptance gates |
| APP | Supplied APP manifest, APP-IG-02, APP-IG-03, APP-R2 | Optional later binding; full APP-2 through APP-5 texts still needed for formal mapping |

The design is a strong foundation for attributable evidence. The primary product work is to complete the identity-to-action relationships, make hardware assurance demonstrable, provide reliable producer delivery, and give reviewers an understandable account of both findings and uncertainty.
