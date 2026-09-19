# Changelog

All notable changes to `github.com/intyga-dev/verify-go` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- **Wire format: the DIV Intent Payload gained a REQUIRED `evidence` field, and it must be `null`.**
  `div-intent-verification` and `div-offline-intent` now carry `"evidence":null` in the signed bytes
  (DIV §4.3.4); `div-delegation`, `div-agent-authority` and `div-platform-intent` deliberately do
  not. `null` is signed and load-bearing, exactly as `requester.attestation`'s null is: it is the
  payload's explicit statement that the authorization was not conditioned on any external fact.
  Verification refuses a payload whose `evidence` key is absent, and refuses any non-`null` value
  rather than treating it as unconditioned — the same fail-closed-on-unknown rule as the
  `signerClass` registry, and checked before Local Payload Reconstruction so an unsupported payload
  shape does not surface as a parameter mismatch. Absent and `null` are distinguished explicitly;
  collapsing them would make the check a no-op. All golden vectors were regenerated.

- Align cross-language receipt and audit verification: platform receipts, agent-authority seals,
  self-certifying DID trust, single/multi-event bundles, embedded ES256 signatures, tenant sequence
  checks, checkpoint continuity, anchor quorum and Rekor. Shared executable fixtures cover valid
  artifacts and refusals; no wire format changes.
- Refuse unknown witness signature algorithms. Require identity-bound trust when the signed
  `requesterCannotApprove` rule is set; key-only trust cannot enforce requester identity. That
  refusal is now reported as itself: it was folded into a per-witness failure and surfaced as
  "quorum not met", so the caller was told its quorum was short when the real answer is that its
  trust anchor is the wrong shape for the signed policy. The verdict is unchanged — no witness
  could ever be counted — and the reason now matches TypeScript, Rust, Java and Python. Applies to
  both `VerifyApprovalReceipt` and `VerifyAgentAuthority`.
- Report `brokenAt` for a partially chained roots file as the first UNCHAINED index instead of a
  hardcoded 0. `brokenAt` is how an operator locates the splice, and entry 0 of a spliced file is
  usually intact. Pinned by the new `mixed-chained-and-unchained` parity vector.

- Recheck a verified delegation's expiry when it is used, under the approval call's `AsOf`, clock
  skew and explicit `AllowExpired` forensic override.
- **Refuse a Go value the canonicalizer cannot canonicalize, instead of guessing with
  `encoding/json`.** `StableStringify` fell through to `encoding/json` for any type outside the JSON
  shapes — so a `map[string]string`, a `float32` or a `uint64` in `Expected.Params` was serialized
  with UTF-8 key ordering, U+2028/U+2029 escaped, and no portable-range check, contradicting the
  shared vectors and producing bytes no other port can reproduce. It now returns an error naming the
  Go type, matching the fail-closed choice in the TypeScript, Rust, Python and Java ports.
  `[]string` — which the canonical builders pass in for `allowedAaguids` and `delegatedTo` — is
  canonicalized properly rather than refused.
- **Refuse a forward-dated offline proof or delegation (DIV §5a.3 rule 3, §5a.6 step 1).** The
  window caps bounded a proof's WIDTH but never its POSITION, so a quorum-signed proof dated years
  ahead with a compliant 60-minute (or 72-hour) window verified today and kept verifying until that
  date. The check is unconditional — the audit/`AllowExpired` override re-examines a proof that was
  valid and has lapsed, and does not reach one dated in the future.
- **Refuse a signed `requirement.requiredApprovals` below 1 (DIV §4.3.2).** §5 step 7's "at least
  `requiredApprovals`" is satisfied vacuously by 0, so the minimum is now enforced explicitly
  instead of by an undocumented floor.

## [1.0.0]

Initial public release.

- Offline approval-receipt verification (ES256 and WebAuthn) against a caller-supplied trust
  anchor — no Intyga secret, no network. Go standard library only.
- Offline approvals (DIV §5a) behind the explicit `AllowOffline` opt-in, with the 60-minute window
  enforced at verification; `VerifyDelegation` for §5a.5 delegations, with the 72-hour window and
  the refusal to let a delegation authorize anything by itself.
- DEWP Core Profile primitives and §5.2 single-anchor signature verification, pinned by the shared
  cross-language golden vectors. §5.3 anchor-quorum evaluation and evidence-bundle parsing are
  deliberately out of scope — see the README's limits section.
