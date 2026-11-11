# Design Document: `jans-trace-core` MVP

## 1. Summary

`jans-trace-core` is a reusable Rust library for the deterministic cryptographic operations required by the Lock Server TRACE MVP. It provides one implementation of TRACE JSON validation, RFC 8785 canonicalization, Ed25519 signing and verification, content-digest calculation, and Lock receipt-chain hashing.

The library is shared infrastructure, not a Lock Server or Cedarling subsystem:

- **Cedarling and other producers** use it to sign TRACE assertions. This includes an **application that embeds Cedarling and enforces its own decisions**: because the crate is a shared library and not a Cedarling subsystem, that application uses it **directly** to build and sign its own `CAPABILITY_INVOKED` as a *second* producer — with its own key, `producer_id`, and chain, distinct from the embedded Cedarling's — rather than asking Cedarling to sign the invocation (which would mix the PDP's and PEP's keys; see `cedarling-trace-design.md`: Embedded enforcement).
- **Lock Server** uses it to verify assertions, compute content digests, and construct receipt-chain hashes.
- **Independent tools** use it to reproduce the same results without trusting Lock.

The crate performs deterministic computation only. It does not authorize capabilities, authenticate API clients, resolve producer keys, allocate receipt sequence numbers, access storage, publish external anchors, or make assurance claims.

## 2. Goals

The MVP must provide:

1. Strict parsing and validation of TRACE JSON used as cryptographic input.
2. RFC 8785 JSON Canonicalization Scheme (JCS) output.
3. Ed25519 signing and verification using the record's signed `kid`.
4. Deterministic `content_digest` calculation over a complete signed assertion.
5. Deterministic Lock receipt-entry hashing for a per-evidence-domain chain.
6. APIs suitable for native Rust callers and a narrow Java binding for Lock Server.
7. Stable error codes that do not expose secrets or depend on Rust implementation details.
8. Normative test vectors usable by Rust, Java, and third-party implementations.
9. Fuzzing and property tests for parser, canonicalization, signature, and receipt-chain behavior.
10. A design that can later support checkpoints, inclusion proofs, external anchors, and Evidence Packet verification without changing MVP outputs.

## 3. Non-goals

The MVP does not provide:

- a blockchain, distributed ledger, consensus protocol, or smart contract;
- Lock receipt sequence allocation or database transactions;
- producer-key registration, discovery, rotation policy, or revocation decisions;
- OAuth validation or evidence-domain derivation;
- TRACE event-kind business-schema validation;
- settlement or completeness assessments;
- signed receipt checkpoints;
- Merkle trees, inclusion proofs, SCITT receipts, or external anchoring;
- Evidence Packet creation;
- token validation, token enrichment, or credential exchange;
- HSM, KMS, or secret-store integrations; or
- network services.

These remain responsibilities of Lock, Cedarling, producer integrations, or later crates.

## 4. Architectural boundaries

```text
TRACE producer (for example, Cedarling)
    └── jans-trace-core
        ├── canonicalize unsigned assertion
        └── create Ed25519 signature

Lock Server ingestion transaction
    ├── derive evidence_domain_id from authenticated API client
    ├── resolve registered producer key
    ├── jans-trace-core
    │   ├── parse and validate cryptographic JSON
    │   ├── verify producer signature
    │   ├── compute content_digest
    │   └── compute receipt hash
    └── persist record, receipt entry, and indexes (Lock MVP §9)

Independent verifier
    └── jans-trace-core
        └── reproduce signature, digest, and receipt-link results
```

### 4.1 Lock remains responsible for evidence ingestion

Lock derives `evidence_domain_id`, validates TRACE API access, resolves `(evidence_domain_id, producer_id, kid)`, enforces event schemas, and stores the accepted record. The library must never accept a producer-supplied evidence domain as authoritative.

### 4.2 Cedarling remains the PDP

Cedarling decides whether a capability is authorized and produces the resulting `AUTHORIZATION_DECISION` assertion. `jans-trace-core` only signs or verifies bytes; it has no authorization-policy behavior.

### 4.3 No network boundary in the ingestion path

The core is an in-process library. A Rust sidecar or remote cryptographic service would introduce availability problems and a distributed transaction into Lock's ingestion path. External anchoring, when added, may run asynchronously because it operates on already-persisted Lock checkpoints.

## 5. Workspace structure

The crate lives in the `jans-cedarling` Cargo workspace of the Janssen monorepo, next to Cedarling, its first producer:

```text
jans-cedarling/
├── Cargo.toml                    # workspace; shared dependency versions
├── jans-trace-core/              # the library
│   ├── src/                      # assertion, signature, key, receipt, inputs, json, self_test
│   ├── tests/rfc8785/            # RFC 8785 reference vectors
│   └── README.md                 # use cases, API, error codes (also the crate docs)
└── bindings/
    ├── jans_trace_uniffi/        # UniFFI export of the core (replaces jans-trace-jni)
    └── jans-trace-java/          # Java facade and Maven module used by Lock
```

Responsibilities:

- **`jans-trace-core`** is the production Rust API. It contains no FFI, CLI, filesystem, database, or network code.
- **`jans_trace_uniffi`** exports the core to the JVM through UniFFI (generated bindings, panics caught at the boundary), so no hand-written JNI or `unsafe` code exists.
- **`jans-trace-java`** is the Java API Lock uses (§9).
- The conformance CLI, the normative **`test-vectors/`**, and **`fuzz/`** are not built yet (§16, `trace-mvp-post-mvp.md` §5.1).

Future anchoring code should be a separate Lock-owned crate or module, not added to `jans-trace-core` unless it is a protocol-neutral verification primitive.

## 6. Cryptographic profile

### 6.1 Algorithms

The MVP profile fixes the following algorithms:

| Purpose | Algorithm |
|---|---|
| JSON canonicalization | RFC 8785 JCS |
| Producer signature | Ed25519 |
| Content digest | SHA-256 |
| Receipt-entry hash | SHA-256 |
| Binary-to-text signature encoding | Unpadded base64url |
| Digest text encoding | `sha256:` followed by 64 lowercase hexadecimal characters |

Algorithm agility is deliberately deferred. Allowing record-selected algorithms in the MVP would add downgrade and interoperability risks. A future profile can introduce new algorithms with a new profile identifier and explicit verifier policy. (The TRACE standard — v0.2, `research/trace-spec.txt` — permits Ed25519, ES256, and ES384; the MVP's **Ed25519-only** choice is a deliberate subset of that set, not a divergence from it, and the broader set is one of the additions a future profile may enable.)

### 6.2 Strict JSON requirements

Cryptographic processing must reject JSON that cannot be represented unambiguously under JCS and I-JSON. At minimum, the parser rejects:

- duplicate object member names at any depth;
- invalid UTF-8 or invalid Unicode scalar values;
- NaN, positive infinity, and negative infinity;
- numeric values that cannot be represented by the supported JCS number model;
- trailing non-whitespace data after the JSON value;
- a top-level value that is not an object;
- missing or incorrectly typed common identity fields required by the operation; and
- a top-level `signature` or `kid` with an invalid representation.

Duplicate-key detection must be implemented explicitly. A normal JSON parser that silently keeps the first or last duplicate is not acceptable for signed input.

The core library validates only cryptographically relevant common structure. Lock separately validates the complete TRACE schema and the `trace.event_kind` discriminated union.

### 6.3 Signature input

The producer signature covers the RFC 8785 canonical form of the complete top-level assertion object with only the top-level `signature` member omitted.

The following fields are therefore signed when present:

- `producer` (the stable logical producer identifier — not a `name/semver` string; software version travels as a separate signed field such as `producer_version`, which is covered here as any other top-level member);
- `kid`;
- `record_id`;
- `trace` and all nested fields;
- `producer_chain` and all nested fields; and
- `parent_record_ids` and all entries.

No other field may be removed merely because it is unknown to the current library version. This preserves forward compatibility: extension fields (for example `producer_version`, or any field a future profile adds) remain protected by the signature even though this crate does not interpret them.

Conceptually:

```text
signature_input = JCS(assertion minus top-level "signature")
signature       = Ed25519.sign(private_key, signature_input)
```

The `kid` is inside the signed scope. Key lookup occurs outside the library, but the caller supplies the expected `kid` and producer identity so the library can reject mismatches.

### 6.4 Signature representation

`signature` is the unpadded base64url encoding of the 64-byte Ed25519 signature. The library rejects padded base64, standard base64 alphabet characters, incorrect decoded length, or a non-string signature.

The library does not accept a producer identity or `kid` from an unsigned HTTP header as a substitute for the values in the assertion.

### 6.5 Content digest

`content_digest` fingerprints the complete signed assertion. It includes the `signature` member and excludes every Lock-derived field.

```text
content_digest_bytes = SHA-256(JCS(complete signed assertion))
content_digest       = "sha256:" + lowercase_hex(content_digest_bytes)
```

Consequences:

- Reformatting semantically identical JSON does not change the digest.
- Changing any signed value or the signature changes the digest.
- `verification`, `ingestion`, settlement, and enrichment metadata never affect it.
- `content_digest` is not a record identifier and does not replace the producer-supplied `record_id`.

### 6.6 Raw input preservation

The library takes JSON text. A `SignedAssertion` keeps the exact text it was parsed from (`as_str`) and offers no way to serialize the record again, but storing it is not the library's job: Lock remains responsible for preserving the exact received serialization when required for future `as-transmitted` external anchoring. JCS bytes cannot reconstruct the original whitespace or member ordering.

## 7. Receipt-chain profile

The MVP receipt chain is maintained independently for each `evidence_domain_id`. It records Lock ingestion order, not producer event order or global real-world time.

### 7.1 Receipt commitment

The hash input is a versioned object with an exact field set:

```json
{
  "receipt_profile": "tag:jans.io,2026:lock-trace-receipt-v1",
  "evidence_domain_id": "01JANS8YQ...",
  "receipt_sequence": 108422,
  "received_at": "2026-09-17T20:15:32.123Z",
  "producer_id": "cedarling-fleet-1",
  "record_id": "9f3e9e2a-6b0e-4b2c-9f6e-3a2f7b0c9d41",
  "content_digest": "sha256:...",
  "prev_receipt_hash": "sha256:..."
}
```

The field set is closed for this profile. Adding fields requires a new `receipt_profile`; silently adding fields to the v1 hash input would make independent reproduction unreliable.

`received_at` must be an RFC 3339 UTC timestamp normalized to `Z`, with millisecond precision. Lock creates it. Producer timestamps are not used to determine receipt order.

### 7.2 Receipt hash

```text
receipt_hash_bytes = SHA-256(JCS(receipt commitment))
receipt_hash       = "sha256:" + lowercase_hex(receipt_hash_bytes)
```

The receipt hash itself is not included in its own input.

### 7.3 Genesis

The first receipt in an evidence-domain chain uses:

```text
receipt_sequence  = 1
prev_receipt_hash = sha256:0000000000000000000000000000000000000000000000000000000000000000
```

The genesis sentinel is a protocol constant, not the SHA-256 hash of an empty byte string.

### 7.4 Receipt allocation remains in Lock

`jans-trace-core` computes a hash from inputs supplied by Lock. It does not allocate the next sequence or determine the chain head.

The original design had Lock lock the chain-head row, assign the sequence, insert the record and its receipt entry, and update the head in one database transaction. Lock's storage has no multi-entry transaction, so Lock claims a receipt position as a `PENDING` entry, stores the record, and settles the entry `COMMITTED`, or `VOID` when the request fails (`Lock-Server-TRACE-MVP-Design.md` §9). Retrying the same record returns its original receipt and does not append a new one.

## 8. Rust API

The public API does not expose `serde_json::Value`. It takes JSON as text (`&str`, the exact bytes received as UTF-8) and encodes each processing state as a type, so a record is parsed once and an operation cannot be applied in the wrong state:

| Module | Items |
|---|---|
| `assertion` | `UnsignedAssertion::parse(text, &Limits)` → `sign(&dyn TraceSigner)` → `SignedAssertion`; `SignedAssertion::parse(text, &Limits)` → `verify(&VerificationContext)` → `VerifiedAssertion`; `as_str`, `signing_input`, `content_digest`, `identity` (`producer`, `kid`, `record_id`, read strictly before verification); `parse_batch` (split a bulk body into per-record results, keeping each record's exact text) and `batch_body` (join signed records without re-serialization) |
| `signature` | `TraceSigner`, `Ed25519Signer` (`from_pkcs8_pem`, `from_secret_bytes`, `public_key`), `SignatureValue` |
| `key` | `PublicKey` (`from_jwk` for an OKP/Ed25519 JWK, `from_bytes`, `thumbprint` = RFC 7638 `sha256:` + hex) |
| `receipt` | `ReceivedAt`, `ReceiptPosition`, `ReceiptCommitment` (`for_assertion`, `from_stored`, `receipt_hash`, `verify_link`), `StoredReceipt`, `ChainHead`, profile constants |
| `inputs` | `compute_bundle_hash(archive bytes)`, `token_fingerprint(token text)`, so every producer derives these values the same way |
| `json` | `canonicalize_json` |
| `self_test` | `self_test()`: known-answer tests for start-up |

There are no free functions such as `sign_assertion` or `verify_assertion`. Each operation has its own error type holding only the errors it can return, each with a stable `code()` (§10). The crate README documents the API with its use cases.

### 8.1 Signing behavior

`UnsignedAssertion::parse` rejects an object that already has a `signature` member, and checks that the signed record will fit the size limits, so a producer catches a record Lock would refuse for size before signing it. `sign` returns the complete signed record as JCS text: the producer never inserts the signature by hand and its own JSON is never mutated. `SignedAssertion::content_digest` gives the value for the next record's `prev_record_hash`.

`SignedAssertion::signing_input` removes exactly one top-level `signature` member after strict duplicate-key validation, for verification tooling.

### 8.2 Signer abstraction

Private keys are hidden behind the `TraceSigner` trait: `kid()` and `sign(message)`, which returns the 64-byte Ed25519 signature. The core provides `Ed25519Signer`, an in-memory signer whose secret is zeroized on drop. HSM and KMS adapters implement the trait outside the core.

### 8.3 Thread safety

All verification, digest, and receipt operations are stateless and safe for concurrent use. The core must contain no global mutable chain state, key cache, sequence counter, clock, or random-number generator used by verification.

## 9. Java API

The binding is UniFFI-generated (no hand-written JNI) behind a Java facade: package `io.jans.trace` in the `jans-trace-java` Maven module, for server-side Java 11. It mirrors the Rust state types as immutable objects:

| Classes | Items |
|---|---|
| `JsonBody`, `Limits` | JSON input as a string, read as UTF-8 unchanged; limits with the core defaults (`with…` to change one) |
| `SignedAssertion` → `VerifiedAssertion` | `parse`, `verify(VerificationContext)`, `text`, `signingInput`, `contentDigest`, `identity` (`AssertionIdentity`) |
| `UnsignedAssertion`, `Ed25519Signer` | `parse`, `sign` with an in-memory Ed25519 key (`fromPkcs8Pem`, `fromSecretBytes`) |
| `Batch`, `BatchRecord` | `parse` splits a bulk body inside the core, keeping each record's exact text; `body` joins signed records (Lock splits bulk bodies itself and does not use `Batch`) |
| `ReceiptCommitment`, `StoredReceipt`, `ReceiptPosition`, `ReceivedAt`, `ChainHead`, `Digest` | `forAssertion`, `fromStored`, `receiptHash`, `verifyLink`; `ChainHead.empty`/`resume`/`append` |
| `PublicKey`, `Inputs`, `Json`, `Profiles` | `fromJwk`, `fromBytes`, `thumbprint`; `computeBundleHash`, `tokenFingerprint`; `canonicalize`; profile constants |
| `SelfTest` | `run()`: the known-answer tests, at start-up |

Binding rules as implemented:

- Rust panics are caught at the UniFFI boundary and never cross into the JVM.
- Each operation throws its own checked exception, all under `TraceException`; `code()` returns the core's stable error code (§10).
- Inputs are checked against `Limits` inside the core.
- The state objects hold native resources between calls (the original rule was "not retained between calls"), so a record's state is visible in its Java type and the record is parsed once.
- The module is published to the Janssen GitHub Packages Maven repository. The published jar carries the native library for linux x86-64 (glibc) only, since the binding exists for Lock; a jar built from source carries the library of its build platform (x86-64 or aarch64).
- Lock uses the binding as its `NATIVE` crypto provider, which fails closed if the library does not load or `SelfTest.run()` fails (`Lock-Server-TRACE-MVP-Design.md` §14). Lock's default provider is its own Java implementation (BouncyCastle); the normative vectors are meant to keep the two identical.

A remote cryptographic sidecar is not the fallback for Lock's ingestion path.

## 10. Error model

Errors have a stable machine-readable code and a non-sensitive description. Suggested categories:

| Code | Meaning |
|---|---|
| `INVALID_JSON` | JSON syntax is invalid. |
| `DUPLICATE_MEMBER` | An object contains the same member name more than once. |
| `NON_CANONICALIZABLE_JSON` | Input violates JCS/I-JSON constraints. |
| `INVALID_ASSERTION_SHAPE` | Common assertion structure is absent or incorrectly typed. |
| `MISSING_SIGNATURE` | Verification input has no top-level signature. |
| `SIGNATURE_ALREADY_PRESENT` | Signing input already contains a signature. |
| `INVALID_SIGNATURE_ENCODING` | Signature is not unpadded base64url or has the wrong length. |
| `SIGNATURE_INVALID` | Ed25519 verification failed. |
| `PRODUCER_MISMATCH` | Signed producer differs from the caller's expected producer. |
| `KID_MISMATCH` | Signed `kid` differs from the selected registered key. |
| `INVALID_PUBLIC_KEY` | Public-key bytes are invalid. |
| `INVALID_DIGEST` | Digest syntax, algorithm prefix, or length is invalid. |
| `INVALID_RECEIPT` | Receipt fields violate the v1 profile. |
| `RECEIPT_LINK_MISMATCH` | The current receipt does not name the expected predecessor hash. |
| `SIZE_LIMIT_EXCEEDED` | Input exceeds the caller-configured limit. |
| `SIGNER_FAILURE` | The configured signer could not create a signature. |
| `INVALID_PRIVATE_KEY` | *(added)* Not an unencrypted PKCS#8 PEM Ed25519 key, or a raw secret that is not 32 bytes. |
| `SELF_TEST_FAILED` | *(added)* A known-answer self-test differed. |
| `INVALID_BATCH` | *(added)* A bulk body is valid JSON but not an array. |
| `INTERNAL_ERROR` | Unexpected implementation failure; no secret details returned. *(Not used: every error has a specific code, and the binding catches panics at the boundary.)* |

Errors must never include private-key bytes, raw tokens, full confidential assertions, or native backtraces in production responses.

Lock's HTTP API does not return these codes: it maps failures to its own error ids (`Lock-Server-TRACE-MVP-Design.md` §11.1, e.g. `SIGNATURE_INVALID` → `invalid_signature`).

## 11. Input limits

The library accepts limits from the embedding application rather than defining deployment policy. The default profile should support limits for:

- maximum assertion bytes;
- maximum JSON depth;
- maximum object members;
- maximum array elements;
- maximum string bytes; and
- maximum canonicalized output bytes.

Limits are applied before or during parsing so an attacker cannot force an unbounded allocation before rejection. Lock's API limit must be equal to or smaller than the corresponding library limit.

Implemented defaults (`Limits::default()`, generous on purpose; Lock's own defaults are stricter): 256 KiB per assertion, depth 32, 1024 members per object, 1024 elements per array, 64 KiB per string, 512 KiB canonical output, and for bulk bodies 8 MiB and 500 records.

Strict JSON as implemented: duplicate members are rejected at any depth (`DUPLICATE_MEMBER`); a byte-order mark or trailing data is `INVALID_JSON`; every number outside ±(2^53−1), however written (`9007199254740993.0`, `1e30`), is rejected (`NON_CANONICALIZABLE_JSON`), because JCS serializes every number as an IEEE-754 double.

## 12. Dependencies and implementation rules

The implementation should minimize cryptographic and serialization dependencies. Candidate dependencies must be evaluated rather than selected solely by popularity.

Required properties include:

- an actively maintained Ed25519 implementation with RFC 8032 test coverage;
- a SHA-256 implementation from the established RustCrypto ecosystem or equivalent;
- a JCS implementation demonstrably conformant with RFC 8785, including number serialization and Unicode handling;
- explicit duplicate-member rejection; and
- unpadded base64url and lowercase hexadecimal encoding.

Rules:

- `jans-trace-core` forbids `unsafe` code; the UniFFI binding needs none of its own.
- Selected dependencies: `ed25519-dalek` 3 (pure Rust, `verify_strict`, zeroized secrets; weak and small-order public keys are rejected), `serde_json_canonicalizer` 0.4 (passes the RFC 8785 reference vectors), `sha2` 0.11, `base64` 0.23.
- Default builds perform no network or filesystem access.
- Dependency features are pinned narrowly to avoid unused parsers or algorithm suites.
- Builds produce an SBOM and run license and vulnerability checks. (`cargo-deny` runs in CI; an SBOM is not produced yet.)
- The project must not claim FIPS compliance merely because it uses standard algorithms; that requires a separately validated cryptographic module and deployment profile.

## 13. Test strategy

> **Status:** the RFC 8785 reference vectors and the Java binding's known-answer tests run in CI. The normative TRACE vectors (§13.1), property tests (§13.2), fuzz targets (§13.3), and cross-language CI (§13.4) are not built yet; see `trace-mvp-post-mvp.md`.

### 13.1 Normative vectors

Every vector includes:

- raw input JSON;
- expected canonical JSON bytes;
- expected signature input;
- public key and non-production test private key;
- expected unpadded base64url signature;
- expected `content_digest`;
- expected acceptance or error code; and
- for receipts, the complete input and expected receipt hash.

Required positive vectors include:

- a minimal `AUTHORIZATION_DECISION` assertion;
- a record with multiple tokens and multiple parent records;
- Unicode keys and values permitted by JCS;
- two differently formatted inputs producing the same canonical bytes and digest;
- a genesis receipt and several linked receipts; and
- separate evidence-domain receipt chains beginning at sequence one.

Required negative vectors include:

- duplicate members at the top level and at nested levels;
- a missing or malformed `kid`;
- producer and expected-producer mismatch;
- padded or malformed signature encoding;
- a one-bit mutation of every signed field class;
- a signature copied from a different assertion;
- a digest computed without the signature;
- an invalid genesis sentinel;
- a receipt sequence of zero;
- a predecessor mismatch; and
- timestamps not normalized to the receipt profile.

### 13.2 Property tests

Property tests verify:

- parse → canonicalize is deterministic;
- canonicalize → parse → canonicalize is idempotent;
- semantically equivalent formatting yields identical signature inputs and digests;
- mutation of signed content invalidates verification;
- content digests change when signatures change;
- receipt-chain verification succeeds for generated valid chains;
- deletion, reordering, insertion, or mutation of a receipt is detected; and
- chains in different evidence domains do not share state.

### 13.3 Fuzzing

Fuzz targets cover:

- strict JSON parsing;
- JCS canonicalization;
- assertion signing-input extraction;
- signature decoding;
- content-digest calculation;
- receipt parsing and hashing; and
- every binding entry point.

The acceptance criterion is no panic, memory-safety violation, unbounded allocation, or inconsistent result for equivalent inputs.

### 13.4 Cross-language conformance

CI runs the same vectors through:

1. the native Rust API;
2. the Java API used by Lock; and
3. any independent Java implementation retained as a packaging fallback.

All implementations must produce byte-identical canonical values, signatures, digests, and receipt hashes.

## 14. Observability

The library returns structured results but emits no application logs by default. The caller may record:

- operation name;
- success or stable error code;
- duration;
- input size;
- producer and `kid` after successful parsing; and
- algorithm/profile identifiers.

The caller must not record private keys, raw tokens, signatures as credentials, or complete confidential assertions merely to diagnose a failure.

Lock should expose metrics for verification failures, canonicalization failures, producer mismatches, digest conflicts, receipt-link failures, and native-library self-test failures.

## 15. Versioning and compatibility

The Rust crate follows semantic versioning. Protocol outputs are controlled separately by explicit profile identifiers.

- A patch or minor crate release must not change output for an existing profile.
- Any change to signature scope, canonicalization, digest encoding, receipt fields, timestamp normalization, or genesis rules requires a new protocol profile.
- Readers must reject unknown receipt profiles unless explicitly configured to support them.
- Test vectors are versioned with the protocol profile and remain available after crate upgrades.
- The crate is published on crates.io, because the published Cedarling crate depends on it; the crate version (released with the same version as Cedarling; the repository holds `0.0.0`) is independent of the protocol profiles.

The MVP uses:

```text
TRACE assertion profile: tag:jans.io,2026:trace-v1
Lock receipt profile:    tag:jans.io,2026:lock-trace-receipt-v1
```

The assertion profile `tag:jans.io,2026:trace-v1` is a **distinct Jans/Lock profile** that extends the TRACE standard (tracked at **v0.2**, `research/trace-spec.txt`, profile `tag:agentrust-io.com,2026:trace-v0.2`); it is intentionally a separate profile tag, not the standard's. See `design.md`: Alignment with TRACE v0.2 for the field mapping. This crate is profile-agnostic about *content* — it signs and hashes whatever assertion bytes it is given under the fixed cryptographic profile above — so a change of assertion profile does not change this crate's outputs, which are governed solely by the signature-scope, canonicalization, digest, and receipt rules in §6–§7.

## 16. Delivery phases

### Phase 1: Core cryptography

- Strict JSON parser and limits.
- RFC 8785 canonicalization.
- Digest type and SHA-256 encoding.
- Ed25519 signing and verification.
- Assertion signing-input extraction.
- Content-digest computation.
- Initial normative vectors.

### Phase 2: Lock receipt support

- Receipt commitment type.
- Genesis validation.
- Receipt hashing and link verification.
- Receipt-chain property tests.
- Lock transaction integration tests.

### Phase 3: Bindings and tooling

- Java binding.
- Native artifact packaging and startup self-test.
- Conformance CLI.
- Cross-language CI.
- Fuzzing gates and performance benchmarks.

Status: Phase 1 and Phase 2 are implemented except the normative vectors and receipt-chain property tests; Lock's transaction integration is Lock's own (`Lock-Server-TRACE-MVP-Design.md` §9). Of Phase 3, the binding (UniFFI instead of JNI), Maven packaging (linux x86-64), and the start-up self-test are done; the conformance CLI, cross-language CI, and fuzzing gates are not.

All three phases are part of the TRACE MVP delivery. The order permits Cedarling record production and standalone verification to stabilize before Lock adopts the native binding.

## 17. MVP acceptance criteria

The library is ready for MVP use when the list below holds. Status: criterion 2 (normative vectors through Rust and Java) and criterion 13 (fuzz targets) are not met yet; criterion 12 is Lock's, and Lock's storage writes the record and its receipt entry as separate steps (`Lock-Server-TRACE-MVP-Design.md` §9).

The criteria:

1. All RFC 8785 and selected RFC 8032 vectors pass.
2. All TRACE normative vectors pass identically through Rust and Java.
3. A Cedarling-produced assertion verifies in Lock without reserialization requirements.
4. Formatting-only changes yield the same signature input and `content_digest`.
5. Any signed semantic change invalidates the signature.
6. `content_digest` includes the signature and excludes Lock-derived metadata.
7. Duplicate JSON members are rejected before cryptographic verification.
8. Receipt hashes are deterministic and bind every v1 receipt field.
9. Missing, reordered, or modified receipt entries are detected.
10. Evidence-domain chains remain independent.
11. An idempotent record retry does not create a new receipt.
12. Lock can persist the record, receipt, indexes, and chain head atomically.
13. Fuzz targets complete the agreed CI duration without a crash or inconsistent result.
14. No private key, raw bearer token, or confidential assertion is written by library logging.
15. The core crate contains no anchoring, blockchain, storage, network, OAuth, or authorization-policy dependency.

## 18. Future extensions

Later crates or modules may add:

- Lock-signed receipt checkpoints;
- Merkle or MMR commitments and inclusion proofs;
- TRACE Registry, SCITT, and blockchain anchor adapters;
- Evidence Packet manifests and offline verification;
- COSE signatures or additional approved algorithms;
- WebAssembly bindings for browser verification; and
- Python, Go, or C-compatible bindings.

These extensions consume immutable MVP assertions and receipts. They must not change the bytes, digests, or receipt hashes already produced under the v1 profiles.
