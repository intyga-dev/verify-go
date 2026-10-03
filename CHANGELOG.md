# Changelog

All notable changes to `github.com/intyga-dev/verify-go` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [1.1.0]

- No code change. The matched set moves together (`pnpm test:versions`); this release carries the
  new `@intyga/sdk` CLI options and the `require-approval` Action update.

## [1.0.0]

- Verify profile-carried WebAuthn audit signatures with caller-trusted signer keys, origin and RP ID.
  Report explicit per-event signature status and key trust; add strict signature acceptance for
  single and bulk evidence. Audit signature checks do not replace full approval-receipt verification.

- **DIV/DEWP 1.0 pre-release correction (2026-09-27 review L15-L18, I7, I8):** signed timestamps use
  one strict RFC 3339 grammar (`time.RFC3339` alone accepted a comma fraction, more than nine fraction
  digits and offsets such as `+24:00`). Every verifier refuses a `canonicalPayload` that is not valid
  UTF-8 or carries an unpaired-surrogate `\u` escape, which `encoding/json` would read as U+FFFD, and
  `StableStringify` refuses invalid UTF-8. A WebAuthn `topOrigin` differing from `origin` is refused.
  `VerifyPlatformReceipt` ignores `RequireUserVerification=false`. A key mapped to two DIDs counts once
  toward a quorum. RSA-PSS anchors require a 32-byte salt and a 2048-bit modulus (was: any salt).
  Divergence evidence is held to the quorum's seq-range and witness-time rules; a Rekor entry
  establishes divergence only with `RekorSubmitterKeys` pinned. Pinned in all five languages by the `verifierInputHardening` parity vectors; no canonical bytes change for valid input.
- **DIV 1.0 pre-release correction (H1):** add `Expected.Requirement *RequirementFloor` and
  `AgentAuthorityExpectation.Requirement`, applied by `VerifyApprovalReceipt`, `VerifyDelegation` and
  `VerifyAgentAuthority`; export `WeakerRequirementReason`. The signed `requirement` is authored by
  the signers, so one approver (possibly the requester) could self-compose a 1-of-1 receipt for a
  3-of-3 four-eyes action and it verified. A weaker signed requirement is now refused before any
  signature is counted when the caller supplies its own rule (DIV §5 step 3d), on approval, offline,
  delegation and agent-authority verification; the reason starts "signed requirement is weaker than
  the relying party's policy". Omitting the floor keeps the previous behaviour, which proves only the
  quorum the signers stated. No signed byte changes; shared parity vectors pin it in all five
  languages. `AgentAuthorityExpectation` gained a field, so a positional (unkeyed) literal of it no
  longer compiles.
- **DEWP evidence verification (1.0 pre-release correction, Sep 2026):** an entry with a canonical
  preimage reads `tenantSeq` only from it (nil ⇒ no counter) and fails when its redaction counter
  disagrees; a preimage under an unknown profile fails; repeated leaves/seqs and inconsistent leaf
  counts fail; a checkpoint with no `ChainHash`/`AnchoredAt` is never anchored. New
  `EvidenceVerifyOptions.TrustedCheckpoints` and `BundleVerifyOptions.TrustedCheckpoint` take
  caller-held roots-file records (a contradicting checkpoint fails; anchors are held to the record; a
  single proof counts a Rekor/TSA anchor only against one). `IsWellFormedAnchor` requires a registered
  algorithm. Pinned by the shared `dewpEvidenceHardening` vectors.
- **DIV 1.0 pre-release correction (PK-11):** under a signed `requireHardwareKey`, a WEBAUTHN witness
  whose signed authenticatorData carries the Backup Eligible or Backup State flag no longer counts
  toward the quorum (DIV §4.4.5 rule 6) — a relying party now catches an issuer that let a synced
  passkey sign a hardware-pinned action. No signed byte changes; shared parity vectors pin it in all
  five languages.
- **Breaking (DEWP 1.0 pre-release correction):** the anchored preimage is now
  `[dailyRoot, timestamp, issuer, algorithm, seqStart, seqEnd, chainHash]`; anchors lacking the
  position fields never verify. External witness times (Rekor `integratedTime`, TSA `genTime`) must
  fall within `maxAnchorLagSeconds` (default 86400) after — or 300 s before — the checkpoint's claimed
  time; anchors must match the checkpoint's seq range, chain hash and `anchoredAt`; evidence-bundle
  chain hashes are recomputed; verdicts expose per-issuer witness times; an optional pinned Rekor
  submitter key is enforced. A supplied root is reported as `rootSource: "caller-supplied"` (was
  `"independent"`).
- A non-empty `allowedAaguids` is refused exactly like `requireHardwareKey`: bare-key witnesses do not
  count and offline proofs are rejected (DIV §4.3.2/§5a.3).

- Add opt-in RFC 3161/CMS verification and quorum/divergence integration through an isolated
  OpenSSL 3 adapter with signer-certificate pinning and explicit CRL or unchecked revocation.
- Bind Rekor trust to `RekorIssuer` for multi-issuer policies so one log cannot impersonate several
  quorum identities; legacy unscoped keys remain valid only for single-issuer policies.

- Enforce DIV §5 identity trust for multi-approver quorums; preserve DIV §4.4.2 ES256
  compatibility for absent/null/unknown witness labels, while refusing AUTO_APPROVED witnesses.
- Validate DEWP protocol, version and declared hash/serialization/Merkle algorithms before
  accepting proof or evidence bundles. Legacy numeric revisions 1/2 remain supported without
  a protocol declaration. Shared cross-language fixtures cover these contracts.

- Use pinned `golang.org/x/text` to validate Unicode NFC in independently asserted agent context;
  the Go verifier is no longer standard-library-only. `go.sum` records the module checksums.
- **Wire format: DIV v1 agent intents now sign `action`, `agent`, `session`, `nbf`, and `exp` instead of ordinary `expiresAt`; `div-agent-authority` requires `parentReceiptHash` (null for a root).** Older §5b seals lacking that key cannot verify under this pre-release profile and must be re-sealed. All canonical producers, five verifier ports and vectors must move together; the ordinary HUMAN/SERVICE intent keeps `expiresAt`.

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


Initial public release.

- Offline approval-receipt verification (ES256 and WebAuthn) against a caller-supplied trust
  anchor — no INTYGA secret and no network.
- Offline approvals (DIV §5a) behind the explicit `AllowOffline` opt-in, with the 60-minute window
  enforced at verification; `VerifyDelegation` for §5a.5 delegations, with the 72-hour window and
  the refusal to let a delegation authorize anything by itself.
- DEWP Core Profile primitives and §5.2 single-anchor signature verification, pinned by the shared
  cross-language golden vectors. §5.3 anchor-quorum evaluation and evidence-bundle parsing are
  deliberately out of scope — see the README's limits section.
