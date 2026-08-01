# verify-go — Offline Intyga receipt verification for Go

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no Intyga secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

Zero third-party dependencies — Go standard library only. Its canonicalization is held byte-identical to the TypeScript, Python, and Rust verifiers by shared cross-language test vectors.

> Status: **not yet published**. Part of the Intyga multi-language verifier set.

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
}, verify.VerifyOptions{})
if !res.OK {
	log.Fatalf("refusing to proceed: %s", res.Reason)
}
```

One byte of drift — a swapped target, an appended region — and verification fails, because the signature was over the exact bytes you just recomputed.

## WebAuthn (passkey) receipts

A passkey assertion harvested at *any* relying party would otherwise verify, so WebAuthn receipts require you to pin the expected origin and RP ID:

```go
res := verify.VerifyApprovalReceipt(receipt, expected, verify.VerifyOptions{
	ExpectedOrigin: "https://app.example.com",
	ExpectedRpID:   "app.example.com",
})
```

`RequireUserVerification` defaults to true (demands the User-Verified flag); set it to a non-nil `false` to accept mere user presence. Policy `AUTO_APPROVED` receipts carry no human signature and fail closed unless you opt in with `AllowAutoApproved: true`.

## DEWP conformance

This port implements the **DEWP Core primitives** ([`docs/DEWP.md`](../../docs/DEWP.md) §9.1):
domain-separated hashing (`0x00`/`0x01`/`0x02`/`0x03`), two-tier Merkle tree construction with
duplicate-last balancing, leaf-to-root inclusion proof verification, the `trust.intyga.audit.v1`
canonical preimage, the `0x03` anchor digest, and **anchor signature (single-anchor, ES256)** —
`VerifyAnchorSignature` checks one issuer's ES256 signature over the raw 32-byte anchor digest
against a caller-resolved SPKI key. Byte parity with the TypeScript reference is locked by the
shared golden vectors in `packages/mcp-schemas/vectors/ledger-vectors.json`.

It does **not** implement, and a caller should not assume:

- **Anchor quorum verification** (§5.3). Single-anchor ES256 signature checking is provided;
  Ed25519/RSA-PSS anchors, evaluating `requiredAnchors` / issuer trust and divergence detection are
  not. `anchorVerified` therefore cannot be established by this port alone.
- **Proof bundle parsing and the §7.1 verification levels.** This port verifies proofs, not envelopes.
- **Evidence bundles, `tenantSeq` gapless validation, and NDJSON streaming** (§9.2 Extended Profile).
- **The §5.4 checkpoint continuity chain (`0x04` domain tag).** Roots-file transport, outside Core
  (DEWP §9.1); implemented by the TypeScript verifier only.

For the rest of the surface — signed multi-anchor quorum, evidence bundles, gapless `tenantSeq`
completeness over committed events, and the four-property verification model — use the TypeScript
verifier (`@intyga/verify`). Note that no
implementation, the TypeScript one included, currently claims the §9.2 **Extended Profile**: the
profile also requires NDJSON evidence streaming (§6.4), which is specified but not yet implemented
anywhere.

## Also available in
- TypeScript — [`@intyga/verify`](https://github.com/intyga-dev/verify)
- Python — [`verify-python`](https://github.com/intyga-dev/verify-python)
- Rust — [`intyga-verify`](https://github.com/intyga-dev/verify-rust)

For a full client that *requests* approvals (not just verifies them), see [`sdk-go`](https://github.com/intyga-dev/sdk-go).

## License

Apache-2.0.
