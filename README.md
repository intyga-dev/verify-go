# verify-go — Offline INTYGA receipt verification for Go

[![Release gated by INTYGA](https://www.intyga.com/badges/release-gated-by-intyga.svg)](https://www.intyga.com/use-cases/package-publishing)

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no INTYGA secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

One pinned third-party dependency, `golang.org/x/text`, supplies Unicode NFC validation for agent context. Cryptographic verification uses the Go standard library. Canonicalization is held byte-identical to the TypeScript, Python, Rust and Java verifiers by shared cross-language test vectors.

> Part of the INTYGA multi-language verifier set (TypeScript, Python, Go, Rust, Java).

## Install

```sh
go get github.com/intyga-dev/verify-go/v2
```

## Verify an approval receipt

```go
import verify "github.com/intyga-dev/verify-go/v2"

tenantID := os.Getenv("INTYGA_TENANT_ID")
if tenantID == "" {
	log.Fatal("INTYGA_TENANT_ID is required")
}

// `expected` is what you are ABOUT to execute. `TenantID` is YOUR configured workspace,
// `Target` is YOUR OWN identifier (Target
// Isolation), `Nonce` is the challenge YOU issued, and `Approvers` is the key set YOU trust —
// all required, and none of them ever read from the receipt.
res := verify.VerifyApprovalReceipt(receipt, verify.Expected{
	TenantID:   &tenantID,
	Target:     "prod-db-cluster-01",
	Nonce:      nonce,
	ActionType: "wipe_production",
	Params:     map[string]interface{}{"target": "prod-db-1"},
	Approvers:  verify.ApproverTrustAnchor{PublicKeys: []string{approverSpkiB64}},
}, verify.VerifyOptions{
	// REQUIRED for passkey receipts (the normal flow): the approval console's exact origin and
	// RP ID, from the trust-anchor file exported in the console (its `webauthn` block).
	ExpectedOrigin: os.Getenv("INTYGA_WEBAUTHN_ORIGIN"),
	ExpectedRpID:   os.Getenv("INTYGA_WEBAUTHN_RP_ID"),
})
if !res.OK {
	log.Fatalf("refusing to proceed: %s", res.Reason)
}
```

Tenant-bound DIV v2 receipts require `TenantID` from independently trusted configuration or an
adopted trust anchor. The signed value must match exactly; never read the expectation from the
receipt. This also applies to platform receipts, delegations and authority chains. Historical v1
receipts remain verifiable only without a tenant expectation and cannot satisfy a tenant-bound gate.

**Quorum trust.** Key-only trust is accepted only for a one-approval requirement without
`requesterCannotApprove`. Multi-approver quorums and separation of duties require a DID/identity
anchor and otherwise fail closed (DIV §5 step 3b). Several credentials for one DID count as one
approver. Delegations require identity trust regardless of quorum size.

**Requirement floor (DIV §5 step 3d).** The signed `requirement` is the signers' own statement: its
signature stops a third party from altering it, not the approvers it constrains from writing a weaker
one. One approver who is also the requester can sign a 1-of-1 payload alone. **Without a floor this
verifier proves only the quorum the signers stated.** When you know the rule, pass it as
`Expected.Requirement = &verify.RequirementFloor{RequiredApprovals: 3, RequesterCannotApprove: true}`
(`AgentAuthorityExpectation.Requirement` for seals). Nil keeps the previous behaviour.
A signed requirement weaker on any field — fewer approvals, no four-eyes or no hardware key where the
floor demands one — is refused before any signature is counted, with a reason starting "signed
requirement is weaker than the relying party's policy"; an equal or stricter one passes. A malformed
floor (quorum below 1) is refused rather than ignored. The same field exists on the delegation
expectation (pass the ordinary rule) and the agent-authority expectation (your sealing policy).

One byte of drift — a swapped target, an appended region — and verification fails, because the signature was over the exact bytes you just recomputed.

## WebAuthn (passkey) receipts

A passkey assertion harvested at *any* relying party would otherwise verify, so WebAuthn receipts require you to pin the expected origin and RP ID:

```go
res := verify.VerifyApprovalReceipt(receipt, expected, verify.VerifyOptions{
	ExpectedOrigin: "https://app.example.com",
	ExpectedRpID:   "app.example.com",
})
```

`RequireUserVerification` defaults to true (demands the User-Verified flag); set it to a non-nil `false` to accept mere user presence (`VerifyPlatformReceipt` ignores it: DIV §5c.3 requires user verification unconditionally). Policy `AUTO_APPROVED` receipts carry no human signature and fail closed unless you opt in with `AllowAutoApproved: true`.

## Offline approvals and delegations

`VerifyDelegation(...)` checks a DIV §5a.5 delegation — a statement, signed in advance by the ordinary quorum, naming local operators who may approve one pre-declared action while the gateway is unreachable. It is a separate function because a delegation authorizes nothing on its own: `VerifyApprovalReceipt` refuses that payload type outright, with no opt-in. Pass the resulting `*VerifiedDelegation` as `VerifyOptions.Delegation` together with `AllowOffline: true` when verifying the offline approval the delegated operators signed. The 60-minute offline window and 72-hour delegation window are enforced here, not merely at mint.

## Platform intents and agent authority

`VerifyPlatformReceipt` verifies DIV §5c hash-only WebAuthn receipts against the platform's own
payload digest, RP ID, nonce, origin and trusted subject keys. `VerifyAgentAuthority` verifies the
human sealing quorum and returns governance evidence describing an agent's scope. Neither artifact
is accepted by `VerifyApprovalReceipt`: a platform intent is a subject attestation and an authority
grant authorizes no action on its own.

## DEWP conformance

This port implements receipt and audit verification across the same artifact types as TypeScript:
domain-separated hashing (`0x00`/`0x01`/`0x02`/`0x03`), two-tier Merkle tree construction with
duplicate-last balancing, leaf-to-root inclusion proof verification **bounded by leaf position**
(§11.1 — range, path length, and self-pairing all checked), the `trust.intyga.audit.v1`
canonical preimage, the `0x03` anchor digest, and **anchor signature verification** —
`VerifyAnchorSignature` checks one issuer's ES256, Ed25519 or RSA-PSS signature over the raw 32-byte anchor digest
against a caller-resolved SPKI key. Byte parity with the TypeScript reference is locked by the
shared golden vectors in `packages/mcp-schemas/vectors/ledger-vectors.json`. It additionally verifies
single and multi-entry proof bundles, embedded ES256 event signatures, gapless committed `tenantSeq`
ranges, the `0x04` checkpoint continuity chain, and §5.3 anchor quorum. Anchor signatures support
ES256, Ed25519 and RSA-PSS. Rekor anchors verify both the pinned-log-key SET and the hashedrekord
binding to this checkpoint. Configure `RekorIssuer` whenever a policy trusts multiple issuers;
legacy unscoped Rekor trust is accepted only for a single-issuer policy. RFC 3161 anchors count only with issuer-specific
`ExternalAnchorKeys.RFC3161` trust and OpenSSL 3. `VerifyRfc3161Anchor` isolates OpenSSL from host
trust and network fetching, pins the signer certificate, and requires offline CRL checking or
explicit `unchecked` revocation. CMS signer digests are restricted to SHA-256, SHA-384, or SHA-512.
`VerificationTime` selects the evaluation instant; its default
rounds the wall clock up by at most one second for fresh fractional timestamps. Historical results
depend on retained CA, intermediate, and CRL material. WEBHOOK and unknown anchors fail closed.

The following limits remain:

- **NDJSON evidence streaming** (§6.4) is not implemented by any verifier, including TypeScript.
- **DIV §4.4.4 verification-code derivation** (the `digests` vector section). The short display
  code is a human-factors aid that MUST NOT be treated as authentication, so this port carries
  `verificationCode` as an unvalidated field and deliberately does not assert those vectors
  (TypeScript and Python do).
- **The document-signing payload** (`canonicalDocumentPayload`). This port carries no document
  canonicalization and does not assert the `documentPayloads` vector section — as `verify-rust`,
  `verify-java` and `sdk-python` also deliberately do not: the section's own note marks it TS-only
  (document signing is a gateway-side ceremony, not part of the relying-party offline surface).
  Approval and ledger canonicalization are unaffected — it is document *signing* that is out of
  scope here.

One Go-specific precision about the canonicalizer. `Expected.Params` is a `map[string]interface{}`,
and only the JSON shapes canonicalize: `map[string]interface{}`, `[]interface{}`, `[]string`,
`string`, `float64`, `int`, `int64`, `bool`, `nil`. Anything else — a `uint64` id, a `float32`, a
`map[string]string` — is REFUSED by type name rather than handed to `encoding/json`, which sorts
object keys by UTF-8 bytes instead of UTF-16 code units, escapes U+2028/U+2029, and applies no
portable-range check. The refusal reads `params are not canonicalizable: …`, deliberately distinct
from the mismatch reason, so a marshalling mistake is never reported as tampering.

No implementation currently claims the complete §9.2 Extended Profile because it also requires
NDJSON evidence streaming (§6.4).

## Also available in
- TypeScript — [`@intyga/verify`](https://github.com/intyga-dev/verify)
- Python — [`verify-python`](https://github.com/intyga-dev/verify-python)
- Rust — [`intyga-verify`](https://github.com/intyga-dev/verify-rust)
- Java — [`verify-java`](https://github.com/intyga-dev/verify-java)

For a full client that *requests* approvals (not just verifies them), see [`sdk-go`](https://github.com/intyga-dev/sdk-go).

## License

Apache-2.0.


### Audit event signatures

The `trust.intyga.audit.v1` profile carries WebAuthn assertion data in the committed
`canonical.metadata.webauthn.authenticatorData` and `clientDataJSON` fields. Both single-proof and
bulk-evidence verification check these assertions when given caller-owned signer trust. This is a
signature over the exact `signedPayload`, not approval quorum, action authorization, hardware
attestation, current credential status or proof that the deploy executed. Verify the full DIV receipt
against the expected operation and approval policy for those authorization checks.

The per-event signature result distinguishes `verified`, `invalid`, `not_checked` (missing trust,
missing material or unsupported algorithm) and `not_applicable` (unsigned/system or AUTO_APPROVED).
A reason accompanies each status. `trusted: true` requires a valid signature under a caller-supplied
key mapped to that signer DID. WebAuthn requires caller-selected origin and RP ID, user presence and
user verification, and refuses cross-origin assertions. Supply COSE keys for WebAuthn and SPKI keys
for ES256. Multiple keys per DID support deliberate key rotation; the evidence's key is never added
to the caller's trusted set.

Without a signature policy, legacy ES256 checks still use the embedded key and report `trusted: false`;
WebAuthn reports `not_checked`. Diagnostic ledger validity does not imply signature validity. The
strict signature option requires **every selected entry** to have a verified, caller-trusted signature;
unsigned, redacted, incomplete and invalid entries fail that option. Anchor quorum is a separate policy.

Set `SignaturePolicy: &AuditSignaturePolicy{TrustedSigners: ..., ExpectedOrigin: ..., ExpectedRpID: ...}`
and `RequireSignatures: true` in bundle/evidence options.

### Execution evidence (DEWP 1.1 §4.7)

`VerifyEvidenceBundle` reports `Execution`: a §4.7.3 check per Evidence Record and a §4.7.4 status
(`confirmed`, `contradicted`, `unconfirmed`, `pending`, `not_reported`) for every approval nonce an
Approval, Dispatch or Evidence Record names — a silent approval reads `not_reported`. Evidence-source
trust is `EvidencePolicy` (`ExecutionEvidencePolicy`), separate from approver trust: an approver key
never vouches for a statement and a source key never vouches for an approval. Each key is a bare
base64 SPKI P-256 key or a `TrustedSourceKey` with `NotBefore`/`NotAfter` (in JSON, a string or an
object with exactly the members `key`, `notBefore`, `notAfter`). A bounded key establishes trust only
when the record's **anchored time** lies inside the interval — the earliest Rekor/TSA witness time
among the anchors that counted toward quorum for the checkpoint the record's **own** inclusion proof
names, and only when its seq lies within the range those anchors were held to (your
`TrustedCheckpoints` record where it states one, else the bundle's first checkpoint for that root);
never another checkpoint's witness, and never the statement's own `observedAt`/`sampledAt`. A bundle
listing one root twice with differing fields is refused. A JSON key entry with any other member, or a
bound that is not a string, still verifies the signature but establishes no trust (`Malformed()`
says why); an entry with no usable key is dropped. Options: `ExecutionNow` (evaluation time, an
input so a status is reproducible), `EvidenceSkewSeconds` (default 30, clock error only),
`MaxEvidenceWindowSeconds` (default 86400; the dispatch's own deadline is cut to it and
`WindowCapped` says so — a negative value for either falls back to its default) and
`RequireExecutionConfirmed`.

A statement binds to any Dispatch Record whose `payloadSha256` matches; Dispatch Records for one nonce
that disagree are reported as `DispatchConflict`. The window is evaluated on the statement's
`sampledAt`; a trusted, bound `contradicted` sampled after the effective deadline is `stale` but
reported as `LateContradiction`. A bound, in-window or late `contradicted` whose signature verified under a
provisioned key that established no trust — no anchored time, outside the interval, or a malformed
entry — is reported as `UntrustedContradiction` (never under an embedded key). Every statement carries
a per-source `sequence`; `Sources` reports each source's `First`/`Last`, the `Gaps` between them and
any `Divergent` counter value signed over two different statements. `RequireExecutionConfirmed` fails
on any nonce not `confirmed`, on an empty report, and on any dispatch conflict, gap, divergence, late
contradiction or untrusted contradiction. The §4.6.1 signature report (`Signatures.Checks`,
`VerifyAuditSignatureWithEvidence`) places a bounded key at the same anchored time, so it and the
statement check agree. `VerifyBundle` evaluates a single proof's statement through step 4 only and
reports it `unbound`; its anchored time needs `TrustedCheckpoint`. `confirmed` means a
caller-trusted source signed an in-window statement — not physical truth (§4.7.6).
