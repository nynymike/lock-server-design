# TRACE MVP — Post-MVP Backlog

## 1. Purpose

The Jans implementation of the TRACE MVP (Lock Server, Cedarling, `jans-trace-core`) is on `main`. While building it, the teams deferred a number of items: some are later phases of the full design, some are gaps the implementation left open, and some are decisions taken only for the MVP. This document lists them in one place, with the reason each was deferred and the condition for coming back to it.

Several items are solutions to a need nobody has stated yet. §2 asks those questions first: each answer changes what Lock and Cedarling must build.

It complements, and does not replace:

- the "Explicitly deferred" list in `Lock-Server-TRACE-MVP-Design.md` §3 and the later phases in `phased-implementation-plan.md` (Phases 2–4), which are not repeated here unless the implementation adds something concrete;
- the per-producer phased paths in `cedarling-trace-design-MVP.md` §8 and the Auth Server and FIDO companions.

Each item: **what**, why it is not in the MVP, and **when** to return to it.

## 2. Questions to answer first

### Q1. Must a Cedarling instance continue its chain across restarts?

Today every start opens a new chain (§4.1). Continuing one means persisting the chain head (`producer_chain_id`, last `sequence_number`, last `content_digest`) after every signed record and loading it at start.

- **Can it be reliable?** Cedarling is a library inside the host process. It loads no state at start, and the host decides how the process ends. A crash, an OOM kill, a pod eviction or a power loss can stop it between sending a record and persisting the head, so the persisted head can lag behind what Lock already holds. A chain resumed from that head reuses positions Lock has: Lock keeps both records and flags them `equivocation_flag`, the signal for a producer that signed two records for one position. The guarantee would be "one chain, unless the process stops abruptly", which is close to what a new chain per start already gives.
- **Which need does it serve?** For example: an auditor expects one chain per instance; records lost in a crash must be visible (Gluu Ledger PRD EV06); fewer chains to store and list. Each may have a cheaper answer, such as `chain_link` from the new genesis to the previous chain (§4.1).
- **What changes in Lock.** With a chain per start, Lock needs `FIRST_OBSERVED` or producer self-registration (Q4), and it stores one chain per start and per pod. With resumed chains, Lock must tell a resume that overlaps stored records apart from equivocation.

### Q2. Must TRACE work in Cedarling's WASM build?

TRACE needs a native build today (§4.4). The WASM build runs in a browser or an edge runtime that the deployment may not control.

- **Where does the signing key live?** In a browser, the page's user can read any key the page holds. A non-extractable WebCrypto key hides the bytes, not the ability to sign. Would an auditor accept a record signed there?
- **Which use case needs it?** A browser app that authorizes locally, an edge worker, a plug-in host: each has a different trust story.
- **Options.** No TRACE in WASM (today). The WASM build sends unsigned decision facts to a trusted host that signs them, which makes the host the producer. Or each WASM instance signs with its own key, registered when it starts.
- **What changes in Lock.** Signing on a host: the record must say which PDP decided, apart from the producer that signed. A key per instance: key registration at instance start (Q4) and many short-lived keys.

### Q3. What must happen when evidence cannot be delivered?

Today Cedarling keeps authorizing, retries for about five minutes, then drops the signed records; a crash loses its in-memory queue (§4.2). Lock sees an outage loss as a permanent gap and does not see a crash loss at all.

- **Is the requirement "never lose a record", or "a lost record is visible and explained"?** The first needs a durable buffer (Cedarling is a library: whose disk?) or back-pressure on authorization. The second needs a way to declare the loss.
- **May a decision be refused because its evidence cannot be recorded (fail closed)?** Today TRACE never changes a decision.
- **What changes in Lock.** A gap declaration from the producer (§3.1), and gap reporting that tells a declared loss from missing records.

### Q4. Who registers a producer chain in production?

In `PRE_REGISTERED`, Lock's default, an operator registers every `producer_chain_id` before the producer sends. In `FIRST_OBSERVED`, a producer holding a registered key opens chains itself. Cedarling opens a chain per start, so it cannot work with `PRE_REGISTERED` without self-registration.

- **What does `PRE_REGISTERED` protect against that key registration does not?** A holder of the registered key can already sign any record. Possible answers: it caps how many chains a leaked key can open; it lets Lock tell a chain that never reported from one that does not exist.
- **What changes in Lock.** The default chain mode (§3.1), or a self-registration endpoint whose authority comes from the fleet SSA (§4.1).

## 3. Lock Server

### 3.1 Defaults and ingestion rules

- **Accept a chain from a later position, not only from its genesis.** In both `chainRegistrationMode` values Lock rejects a non-genesis record of an unregistered chain (`chain_not_registered`), while the original MVP design's out-of-order rule (`Lock-Server-TRACE-MVP-Design.md` §8 before this update) accepted it with `coverage_gap_flag`. Producers work around it by sending the genesis alone first (Cedarling does). **When:** a producer cannot guarantee genesis-first delivery, e.g. records arriving through several forwarders, or a genesis lost for good.
- **`FIRST_OBSERVED` as the default chain mode.** The default is `PRE_REGISTERED`, so a producer that opens a chain per start (Cedarling, ephemeral pods) is refused until an operator changes the setting. **When:** Q4 is answered; before Cedarling TRACE is enabled in shipped deployments.
- **Self-submission without an allowlist entry.** Lock requires the signed `producer` in the client's `allowedProducerIds` even when a client submits its own records, and a client without its own binding gets `defaultAllowedProducerIds`, empty by default. With the defaults Lock refuses every Cedarling record. **When:** before Cedarling TRACE is enabled in shipped deployments, together with the chain-mode default.
- **`NATIVE` (`jans-trace-core`) as the default crypto provider, and retiring the Java implementation.** Lock defaults to its BouncyCastle implementation; the shared library is opt-in. Two implementations can drift: the Java JCS writes integers beyond ±(2^53−1) as exact digits, where RFC 8785 requires the double form and the core rejects them. **When:** the normative vectors (§5.1) pass through both implementations. FIPS builds stay on `JAVA`: the FIPS WAR ships without the native provider.
- **Atomic record and receipt write.** The ORM has no multi-entry transaction, so the record and its receipt entry are separate writes with `PENDING`/`COMMITTED`/`VOID` states (§9 of the MVP design). **When:** the ORM gains multi-entry transactions, or Lock moves TRACE to a store that has them.
- **Re-receipt operation for a record stored under a `VOID` entry.** After the rare late-insert race the record's identity stays blocked until an operator acts. **When:** the race is observed in production.
- **Quarantine store for rejected records.** Rejected records are not stored. **When:** operators need to inspect refused records.
- **Publish limits and mode in the configuration document.** `maxBulkRecords`, `maxBulkRequestBytes`, and `chainRegistrationMode` are not in `/.well-known/lock-server-configuration`, and with the default `errorReasonEnabled: false` a refused bulk request does not say which limit it hit. **When:** producers must adapt to a Lock configured below its defaults without manual coordination.
- **A way for a producer to declare a gap and its cause.** A producer that gives up on records during a long outage leaves a permanent `coverage_gap_flag` that cannot be told apart from suppressed records. **When:** Q3 is answered.

### 3.2 Scale

- **Ingest throughput.** On a single-node test stand (PostgreSQL, one Lock node), Lock accepts about 100–120 records/s on one producer chain and about 410 records/s on four, with a median near 1 s per 100-record batch. PostgreSQL spends most of its time waiting on commits, the likely limit; this was not verified per chain. The Gluu Ledger PRD (§7) proposes 5,000 records/s sustained with p95 ≤ 500 ms per 100-record batch for the first commercial release. **When:** before that release.

### 3.3 Operations

- **Management through the config-api Lock plugin and the Jans CLI/TUI** (producer keys, chains, TRACE settings). The admin API exists; the tools do not use it yet. **When:** before operators manage producers without `curl`.

## 4. Cedarling

### 4.1 Producer chain

- **Producer self-registration for `PRE_REGISTERED` deployments.** Cedarling opens a new chain with a random id at every start, so an operator cannot pre-register it. Self-registration needs a Lock endpoint, with authority from the fleet SSA rather than from the pod. **When:** Q4 is answered and Lock offers such an endpoint.
- **Durable chain state across restarts.** Every start opens a new chain. **When:** Q1 is answered.
- **`chain_link` from a new genesis to the previous chain head.** Not emitted; the link between chains shows only in Cedarling's log. **When:** the full design's link validation is implemented in Lock and the core, and Q1 needs it.
- **Several chains (lanes) per instance.** Permitted by the MVP design; Cedarling runs one, and more would not raise throughput. A chain signs strictly in order, because each record's `prev_record_hash` is the digest of the previous signed record, so one chain uses one core. On it Cedarling signs about 25,000 records/s (`trace_emitter_throughput` benchmark against a mock Lock, Jans `main` 802b0e0176c, a developer machine). That is about 200 times what Lock accepts from one chain on the test stand (§3.2), and above the Gluu Ledger PRD target for a whole Lock (5,000 records/s). **When:** Lock ingests more from one instance than one chain can sign.

### 4.2 Delivery

- **Records lost to a long Lock outage.** After its retries (about five minutes with the defaults) Cedarling drops signed records, and Lock shows a permanent gap. Options: keep retrying with a capped pause while running, a disk buffer, or a gap declaration (§3.1). **When:** Q3 is answered.
- **Records lost when the Cedarling process crashes.** The queue and the batch in flight live in memory; unlike an outage, Lock does not see this loss, because the next start opens a new chain. The Gluu Ledger PRD (EV06) asks for this to be visible. **When:** Q1 and Q3 are answered, before the first commercial release.
- **Splitting a batch Lock refuses for size.** Cedarling logs one error naming the settings and drops the batch. **When:** Lock does not publish its limits (§3.1) and deployments change them without coordinating.
- **Proactive token renewal before `expires_in`.** Cedarling renews on `401`, which costs one extra request per token lifetime. **When:** that request becomes noticeable.
- **Signing the next batch while the current one is in flight.** **When:** batch latency, not Lock, becomes the limit.

### 4.3 What is recorded

- **`producer_version`.** Optional, a build label only; not emitted in the MVP. **When:** auditors need the build that signed a record.
- **Selective emission (`CEDARLING_TRACE_EMISSION: configured_capabilities`).** Not wired; the full design must first say where the `(action, resource_type)` allow-list lives. The Gluu Ledger PRD (CD03) adds requirements: capture-configuration changes recorded, exclusions and sampling visible, and no silent dropping of `DENY` for captured pairs. **When:** the bulk path cannot keep up, or deployments ask for it.
- **`CEDARLING_TRACE_CHAIN_GENESIS`.** Only `first_observed` exists, so there is no switch. **When:** self-registration (§4.1) adds `pre_registered`.
- **Token enrichment and operation binding** (`validation_at_decision`, `token_claims[]`, request/tool-call digests). Full design Phases 2–3.
- **Token `fingerprint` for X.509 workload credentials** (SHA-256 of the DER form). **When:** certificates are passed as tokens.
- **Diagnostics that separate emitted, queued, omitted, and failed evidence per decision** (Gluu Ledger PRD CD02). In the MVP `emitted` means "queued for the emitter"; acceptance by Lock shows only in metrics. **When:** confirmed as a commercial-release requirement.

### 4.4 Platforms and keys

- **WASM producer.** TRACE requires a native build. **When:** Q2 is answered.
- **Keys outside a PEM file and non-Ed25519 keys** (HSM/KMS through the core's `TraceSigner`, hardware-backed workload keys; Gluu Ledger PRD HW02/HW03). **When:** before the first commercial release; a non-Ed25519 algorithm needs a new profile.
- **Latency percentiles of the TRACE overhead.** Benchmarks measure means and emitter throughput; the Gluu Ledger PRD (§7, CD03) asks for p50/p95/p99 with TRACE on and its overhead separate from policy evaluation. **When:** before the first commercial release.
- **Faster record serialization** (signing the record without an intermediate JSON value; a streaming JCS writer). **When:** signing CPU, not Lock, becomes the limit.

## 5. `jans-trace-core` and bindings

### 5.1 Conformance

- **Normative test vectors** (`test-vectors/`, `manifest.json`; `jans-trace-core-mvp-design.md` §13.1), property tests (§13.2), **fuzz targets** (§13.3), and **cross-language CI** through Rust and Java (§13.4). Core acceptance criteria 2 and 13 depend on them. **When:** before Lock retires its Java implementation (§3.1); they are the contract that keeps the two equal until then.
- **Conformance CLI** (canonicalize, sign, verify, digest, receipt over the vectors). Proposed as a `trace` subcommand of the existing `cedarling-cli` instead of a new `jans-trace-cli` crate. The core design defines the CLI as a development and conformance utility outside Lock's runtime, and `cedarling-cli` is such a tool in the same workspace, already built on Cedarling and so on the core. **When:** with the vectors.
- **SBOM** for the crate and the binding. `cargo-deny` already runs. **When:** release packaging requires it.

### 5.2 Java binding

- **Foreign `TraceSigner` in the Java binding** (HSM/KMS signing from Java). The binding signs only with an in-memory key (`Ed25519Signer`). **When:** a Java producer needs it (§6).

## 6. Other producers

- **Java producers** (Auth Server, FIDO Server, embedded PEPs on the JVM) signing through `jans-trace-java`, which already signs with an in-memory key; a key in an HSM or KMS needs §5.2. The Auth Server and FIDO companions keep these out of the MVP.
- **Embedded PEP emitting `CAPABILITY_INVOKED`** through `jans-trace-core`, and moving the producer-chain logic from Cedarling into the core once a second Rust producer exists.
