# verify-go — Offline SÄKRA receipt verification for Go

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no SÄKRA secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

Zero third-party dependencies — Go standard library only. Its canonicalization is held byte-identical to the TypeScript, Python, and Rust verifiers by shared cross-language test vectors.

> Status: **not yet published**. Part of the SÄKRA multi-language verifier set.

## Install

```sh
go get github.com/sakra-trust/verify-go
```

## Verify an approval receipt

```go
import verify "github.com/sakra-trust/verify-go"

// `expected` is what you are ABOUT to execute; `nonce` is the challenge YOU issued.
res := verify.VerifyApprovalReceipt(receipt, verify.Expected{
	Nonce:      nonce,
	ActionType: "wipe_production",
	Params:     map[string]interface{}{"target": "prod-db-1"},
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

## Also available in
- TypeScript — [`@sakra-trust/verify`](https://github.com/SAKRA-trust/verify)
- Python — [`verify-python`](https://github.com/SAKRA-trust/verify-python)
- Rust — [`sakra-verify`](https://github.com/SAKRA-trust/verify-rust)

For a full client that *requests* approvals (not just verifies them), see [`sdk-go`](https://github.com/SAKRA-trust/sdk-go).

## License

Apache-2.0.
