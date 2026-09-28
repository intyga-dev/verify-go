# verify-go — Offline Intyga receipt verification for Go

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no Intyga secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

One pinned third-party dependency, `golang.org/x/text`, supplies Unicode NFC validation for agent context. Cryptographic verification uses the Go standard library. Canonicalization is held byte-identical to the TypeScript, Python, Rust and Java verifiers by shared cross-language test vectors.

> Part of the Intyga multi-language verifier set (TypeScript, Python, Go, Rust, Java).

## Install

```sh
go get github.com/intyga-dev/verify-go
```

## Verify an approval receipt

```go
import verify "github.com/intyga-dev/verify-go"

// `expected` is what you are ABOUT to execute. `Target` is YOUR OWN identifier (Target
// Isolation), `Nonce` is the challenge YOU issued, and `Approvers` is the key set YOU trust —
// all required, and none of them ever read from the receipt.
res := verify.VerifyApprovalReceipt(receipt, verify.Expected{
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
