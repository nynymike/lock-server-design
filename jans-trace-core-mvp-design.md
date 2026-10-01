# Design Document: `jans-trace-core` MVP

## 1. Summary

`jans-trace-core` is a reusable Rust library for the deterministic cryptographic operations required by the Lock Server TRACE MVP. It provides one implementation of TRACE JSON validation, RFC 8785 canonicalization, Ed25519 signing and verification, content-digest calculation, and Lock receipt-chain hashing.

The library is shared infrastructure, not a Lock Server or Cedarling subsystem:

- **Cedarling and other producers** use it to sign TRACE assertions.
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
6. APIs suitable for native Rust callers and a narrow Java/JNI binding for Lock Server.
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
    └── atomically persist record, receipt, indexes, and chain head

Independent verifier
    └── jans-trace-core
        └── reproduce signature, digest, and receipt-link results
```

### 4.1 Lock remains responsible for evidence ingestion

Lock derives `evidence_domain_id`, validates TRACE API access, resolves `(evidence_domain_id, producer_id, kid)`, enforces event schemas, and stores the accepted record. The library must never accept a producer-supplied evidence domain as authoritative.

### 4.2 Cedarling remains the PDP

Cedarling decides whether a capability is authorized and produces the resulting `AUTHORIZATION_DECISION` assertion. `jans-trace-core` only signs or verifies bytes; it has no authorization-policy behavior.

### 4.3 No network boundary in the ingestion path

The core is an in-process library. A Rust sidecar or remote cryptographic service would introduce availability problems and a distributed transaction into Lock's atomic ingestion path. External anchoring, when added, may run asynchronously because it operates on already-persisted Lock checkpoints.

## 5. Workspace structure

The initial Rust workspace contains:

```text
jans-trace/
├── Cargo.toml
├── crates/
│   ├── jans-trace-core/
│   │   ├── src/
│   │   │   ├── canonical.rs
│   │   │   ├── digest.rs
│   │   │   ├── error.rs
│   │   │   ├── json.rs
│   │   │   ├── receipt.rs
│   │   │   ├── signature.rs
│   │   │   ├── types.rs
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   ├── jans-trace-jni/
│   │   ├── src/lib.rs
│   │   └── Cargo.toml
│   └── jans-trace-cli/
│       ├── src/main.rs
│       └── Cargo.toml
├── test-vectors/
│   ├── assertions/
│   ├── receipts/
│   └── manifest.json
└── fuzz/
```

Responsibilities:

- **`jans-trace-core`** is the production Rust API. It contains no JNI, CLI, filesystem, database, or network code.
- **`jans-trace-jni`** exposes the small set of stateless operations Lock requires.
- **`jans-trace-cli`** is a development and conformance utility. It is not part of Lock's runtime architecture.
- **`test-vectors`** is normative interoperability data shared with Java and external implementations.

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

Algorithm agility is deliberately deferred. Allowing record-selected algorithms in the MVP would add downgrade and interoperability risks. A future profile can introduce new algorithms with a new profile identifier and explicit verifier policy.

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

- `producer`;
- `kid`;
- `record_id`;
- `trace` and all nested fields;
- `producer_chain` and all nested fields; and
- `parent_record_ids` and all entries.

No other field may be removed merely because it is unknown to the current library version. This preserves forward compatibility: extension fields remain protected by the signature.

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

The library accepts raw JSON bytes but returns computed values; it does not retain the bytes. Lock remains responsible for preserving the exact received serialization when required for future `as-transmitted` external anchoring. JCS bytes cannot reconstruct the original whitespace or member ordering.

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

### 7.4 Atomicity remains in Lock

`jans-trace-core` computes a hash from inputs supplied by Lock. It does not allocate the next sequence or determine the chain head.

Lock must perform these steps in one database transaction:

1. Lock the evidence-domain chain-head row.
2. Read the current sequence and receipt hash.
3. Assign the next sequence and `received_at`.
4. Call `jans-trace-core` to compute the next receipt hash.
5. Insert the immutable assertion, envelope, receipt entry, and indexes.
6. Update the chain-head row.
7. Commit.

On failure, none of these writes may become visible. Retrying the same record must return its original receipt and must not append a new receipt.

## 8. Rust API

The public API should operate on byte slices and small explicit context structures. It must not expose `serde_json::Value` as the stable external API because doing so would couple callers to implementation-specific parsing behavior.

Illustrative API:

```rust
pub struct VerificationContext<'a> {
    pub expected_producer: &'a str,
    pub expected_kid: &'a str,
    pub public_key: &'a [u8; 32],
}

pub struct VerifiedAssertion {
    pub producer: String,
    pub kid: String,
    pub record_id: String,
    pub signature_input_sha256: Digest,
    pub content_digest: Digest,
}

pub struct ReceiptCommitment<'a> {
    pub receipt_profile: &'a str,
    pub evidence_domain_id: &'a str,
    pub receipt_sequence: u64,
    pub received_at: &'a str,
    pub producer_id: &'a str,
    pub record_id: &'a str,
    pub content_digest: &'a Digest,
    pub prev_receipt_hash: &'a Digest,
}

pub fn canonicalize_json(input: &[u8]) -> Result<Vec<u8>, TraceError>;

pub fn assertion_signing_input(
    unsigned_or_signed_assertion: &[u8],
) -> Result<Vec<u8>, TraceError>;

pub fn sign_assertion(
    unsigned_assertion: &[u8],
    signer: &dyn TraceSigner,
) -> Result<SignatureValue, TraceError>;

pub fn verify_assertion(
    signed_assertion: &[u8],
    context: &VerificationContext<'_>,
) -> Result<VerifiedAssertion, TraceError>;

pub fn compute_content_digest(
    signed_assertion: &[u8],
) -> Result<Digest, TraceError>;

pub fn compute_receipt_hash(
    receipt: &ReceiptCommitment<'_>,
) -> Result<Digest, TraceError>;

pub fn verify_receipt_link(
    previous_receipt_hash: &Digest,
    current: &ReceiptCommitment<'_>,
) -> Result<Digest, TraceError>;
```

### 8.1 Signing behavior

`sign_assertion` requires an object without a `signature` member. It returns the signature value; it does not mutate caller JSON. The producer inserts that value as the top-level `signature` and may then call `compute_content_digest` on the complete assertion.

`assertion_signing_input` may accept a signed assertion for verification tooling, but it removes exactly one top-level `signature` member after strict duplicate-key validation.

### 8.2 Signer abstraction

Private keys should be hidden behind a trait:

```rust
pub trait TraceSigner: Send + Sync {
    fn kid(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], TraceError>;
}
```

The core crate may provide an in-memory Ed25519 signer for tests and simple deployments. HSM and KMS adapters belong outside the core and implement the trait. Secret-key buffers must use zeroization where the selected cryptographic backend permits it.

### 8.3 Thread safety

All verification, digest, and receipt operations are stateless and safe for concurrent use. The core must contain no global mutable chain state, key cache, sequence counter, clock, or random-number generator used by verification.

## 9. Java/JNI API

Lock requires only stateless JNI calls. The Java-facing surface should use byte arrays and JSON result objects rather than exposing Rust object lifetimes.

Suggested Java interface:

```java
public final class JansTraceCore {
    public static VerificationResult verifyAssertion(
        byte[] assertion,
        String expectedProducer,
        String expectedKid,
        byte[] ed25519PublicKey);

    public static String computeContentDigest(byte[] assertion);

    public static String computeReceiptHash(ReceiptCommitment receipt);

    public static byte[] canonicalizeJson(byte[] input);
}
```

JNI requirements:

- No Rust panic may cross the JNI boundary; all entry points use panic containment.
- Java receives stable error codes plus safe diagnostic text.
- The wrapper places explicit maximum sizes on byte-array inputs before allocation.
- Native resources are not retained between calls.
- Platform artifacts are published for every supported Lock runtime and verified during startup.
- Lock fails closed for TRACE ingestion if the native library cannot load or its self-test fails.

If native packaging proves unacceptable for an initial Lock deployment, the normative test vectors permit a Java implementation to reproduce the profile. A remote cryptographic sidecar is not the fallback for the atomic ingestion path.

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
| `INTERNAL_ERROR` | Unexpected implementation failure; no secret details returned. |

Errors must never include private-key bytes, raw tokens, full confidential assertions, or native backtraces in production responses.

## 11. Input limits

The library accepts limits from the embedding application rather than defining deployment policy. The default profile should support limits for:

- maximum assertion bytes;
- maximum JSON depth;
- maximum object members;
- maximum array elements;
- maximum string bytes; and
- maximum canonicalized output bytes.

Limits are applied before or during parsing so an attacker cannot force an unbounded allocation before rejection. Lock's API limit must be equal to or smaller than the corresponding library limit.

## 12. Dependencies and implementation rules

The implementation should minimize cryptographic and serialization dependencies. Candidate dependencies must be evaluated rather than selected solely by popularity.

Required properties include:

- an actively maintained Ed25519 implementation with RFC 8032 test coverage;
- a SHA-256 implementation from the established RustCrypto ecosystem or equivalent;
- a JCS implementation demonstrably conformant with RFC 8785, including number serialization and Unicode handling;
- explicit duplicate-member rejection; and
- unpadded base64url and lowercase hexadecimal encoding.

Rules:

- `jans-trace-core` should forbid `unsafe` code.
- Any unavoidable `unsafe` code is isolated in `jans-trace-jni`, documented, and reviewed.
- Default builds perform no network or filesystem access.
- Dependency features are pinned narrowly to avoid unused parsers or algorithm suites.
- Builds produce an SBOM and run license and vulnerability checks.
- The project must not claim FIPS compliance merely because it uses standard algorithms; that requires a separately validated cryptographic module and deployment profile.

## 13. Test strategy

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
- every JNI entry point.

The acceptance criterion is no panic, memory-safety violation, unbounded allocation, or inconsistent result for equivalent inputs.

### 13.4 Cross-language conformance

CI runs the same vectors through:

1. the native Rust API;
2. the Java/JNI API used by Lock; and
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

The MVP uses:

```text
TRACE assertion profile: tag:jans.io,2026:trace-v1
Lock receipt profile:    tag:jans.io,2026:lock-trace-receipt-v1
```

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

- Java/JNI wrapper.
- Native artifact packaging and startup self-test.
- Conformance CLI.
- Cross-language CI.
- Fuzzing gates and performance benchmarks.

All three phases are part of the TRACE MVP delivery. The order permits Cedarling record production and standalone verification to stabilize before Lock adopts the native binding.

## 17. MVP acceptance criteria

The library is ready for MVP use when:

1. All RFC 8785 and selected RFC 8032 vectors pass.
2. All TRACE normative vectors pass identically through Rust and Java/JNI.
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
