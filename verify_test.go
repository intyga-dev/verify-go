package verify

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

// TestCanonicalIntentPayloadParity pins the ordinary intent payload against a HARDCODED literal.
// The shared vectors file (TestIntentCanonicalParity in vectors_test.go) is the authoritative pin;
// this literal deliberately stays alongside it as a generator-independent second pin, so a bug that
// drifts the vector generator and this port together still trips something.
func TestCanonicalIntentPayloadParity(t *testing.T) {
	params := map[string]interface{}{
		"zeta":  float64(1),
		"alpha": float64(2),
		"mid": map[string]interface{}{
			"z": float64(1),
			"a": float64(2),
		},
	}
	req := RequesterIdentity{
		DID:         "did:intyga:service:deploy-pipeline",
		Attestation: nil,
	}

	// Deliberately UNSORTED allowedAaguids: the builder sorts, and this pins that it does.
	requirement := ApprovalRequirement{
		RequiredApprovals:      2,
		RequireHardwareKey:     true,
		AllowedAaguids:         []string{"b-aaguid", "a-aaguid"},
		RequesterCannotApprove: true,
		SignerClass:            "human",
	}

	got, err := CanonicalIntentPayload("prod-db-cluster-01", "deleteDatabase", "Delete staging database", params, req, requirement, "c_8f91a2", "2026-07-23T19:30:00Z")
	if err != nil {
		t.Fatalf("CanonicalIntentPayload refused portable input: %v", err)
	}
	// Strict RFC 8785 JCS: every key sorted; type/version last. Byte-for-byte the string the TS
	// reference implementation (@intyga/mcp-schemas) emits for the same input.
	expected := `{"actionType":"deleteDatabase","display":"Delete staging database","expiresAt":"2026-07-23T19:30:00Z","nonce":"c_8f91a2","params":{"alpha":2,"mid":{"a":2,"z":1},"zeta":1},"requester":{"attestation":null,"did":"did:intyga:service:deploy-pipeline"},"requirement":{"allowedAaguids":["a-aaguid","b-aaguid"],"requesterCannotApprove":true,"requireHardwareKey":true,"requiredApprovals":2,"signerClass":"human"},"target":"prod-db-cluster-01","type":"div-intent-verification","v":1}`

	if got != expected {
		t.Fatalf("CanonicalIntentPayload mismatch:\nGot:  %s\nWant: %s", got, expected)
	}
}

// ─── July 2026 audit regressions ────────────────────────────────────────────

// TestAutoApprovedStillBindsTargetAndParams pins DIV §5: opting in to AUTO_APPROVED waives the
// SIGNATURE requirement (step 6/7), never the target-binding and expiry steps (8 and 9).
//
// The accept used to sit immediately after the nonce comparison, so a receipt was attested having
// proven only that its nonce matched. An agent holding a nonce for a trivial action could get it
// auto-approved by policy and present that receipt for a destructive call.
func TestAutoApprovedStillBindsTargetAndParams(t *testing.T) {
	autoApproved := "AUTO_APPROVED"
	requester := RequesterIdentity{DID: "did:intyga:service:agent", Attestation: nil}
	requirement := ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human"}

	// What was actually approved: a harmless read on a sandbox, long expired.
	approved, err := CanonicalIntentPayload(
		"sandbox-cluster", "listFiles", "List files",
		map[string]interface{}{"path": "/tmp"},
		requester, requirement, "c_nonce_1", "2020-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("CanonicalIntentPayload refused portable input: %v", err)
	}
	receipt := ApprovalReceipt{
		CanonicalPayload:  approved,
		ActionDescription: "List files",
		Params:            map[string]interface{}{"path": "/tmp"},
		SigAlg:            &autoApproved,
		Requester:         &requester,
	}

	// What the relying party is about to execute: something else entirely.
	destructive := Expected{
		Target:     "prod-db-cluster-01",
		Nonce:      "c_nonce_1",
		ActionType: "deleteDatabase",
		Params:     map[string]interface{}{"environment": "production"},
		Approvers:  ApproverTrustAnchor{PublicKeys: []string{}},
	}

	if r := VerifyApprovalReceipt(receipt, destructive, VerifyOptions{AllowAutoApproved: true}); r.OK {
		t.Fatalf("auto-approved receipt for a DIFFERENT action was accepted: %+v", r)
	}

	// Refused by default even when everything else lines up.
	matching := Expected{
		Target:     "sandbox-cluster",
		Nonce:      "c_nonce_1",
		ActionType: "listFiles",
		Params:     map[string]interface{}{"path": "/tmp"},
		Approvers:  ApproverTrustAnchor{PublicKeys: []string{}},
	}
	if r := VerifyApprovalReceipt(receipt, matching, VerifyOptions{}); r.OK {
		t.Fatalf("AUTO_APPROVED must be refused without opt-in: %+v", r)
	}
	// And still expiry-checked once opted in.
	if r := VerifyApprovalReceipt(receipt, matching, VerifyOptions{AllowAutoApproved: true}); r.OK {
		t.Fatalf("a 2020-expired auto-approval must not verify: %+v", r)
	}
	// The genuine case: matching action, opted in, expiry waived for re-verification.
	r := VerifyApprovalReceipt(receipt, matching, VerifyOptions{AllowAutoApproved: true, AllowExpired: true})
	if !r.OK {
		t.Fatalf("a matching, opted-in auto-approval should verify, got: %+v", r)
	}
	if !r.AutoApproved {
		t.Fatal("AutoApproved should be reported so the caller knows no human signed")
	}
}

// TestStableStringifyDoesNotHTMLEscape pins the canonicalizer against Go's encoding/json default,
// which escapes <, > and & where JSON.stringify and RFC 8785 do not. Divergence here made this
// verifier report a perfectly valid approval as "target/params/actionType do not match".
func TestStableStringifyDoesNotHTMLEscape(t *testing.T) {
	cases := map[string]string{
		"Pay Alice & Bob <urgent>": `"Pay Alice & Bob <urgent>"`,
		"a&b":                      `"a&b"`,
		"<script>":                 `"<script>"`,
	}
	for in, want := range cases {
		got, err := StableStringify(in)
		if err != nil {
			t.Errorf("StableStringify(%q) errored: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("StableStringify(%q) = %s, want %s", in, got, want)
		}
	}

	// Also in object KEYS and nested inside a full canonical payload.
	got, err := StableStringify(map[string]interface{}{"a&b": "x<y"})
	if err != nil {
		t.Fatalf("StableStringify errored: %v", err)
	}
	if want := `{"a&b":"x<y"}`; got != want {
		t.Errorf("key escaping: got %s, want %s", got, want)
	}

	requester := RequesterIdentity{DID: "did:intyga:service:deploy", Attestation: nil}
	requirement := ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human"}
	payload, err := CanonicalIntentPayload(
		"https://api.example.com/v1?a=1&b=2", "transfer", "Transfer to Acme & Co",
		map[string]interface{}{"note": "<redacted>"},
		requester, requirement, "c_1", "2026-07-24T12:00:00Z",
	)
	if err != nil {
		t.Fatalf("CanonicalIntentPayload refused portable input: %v", err)
	}
	// The escaped forms are what must be absent; the raw characters are correct and expected.
	for _, r := range []rune{'&', '<', '>'} {
		escaped := fmt.Sprintf("\\u%04x", r) // the \uXXXX form encoding/json emits by default
		if strings.Contains(payload, escaped) {
			t.Fatalf("canonical payload contains Go-escaped %q: %s", escaped, payload)
		}
	}
	if !strings.Contains(payload, "Transfer to Acme & Co") {
		t.Fatalf("expected the raw ampersand to survive canonicalization: %s", payload)
	}
}

// ─── Non-portable numbers (August 2026 audit) ───────────────────────────────

// TestStableStringifyRefusesNonPortableFloats pins the portability rules mirrored from
// isPortableNumber in @intyga/mcp-schemas: a number outside the agreed range serializes
// differently across the TS/Go/Rust/Python ports, so it must be refused rather than signed over.
// Go used to normalize silently — and its float64→int64 cast overflowed above 2^63.
func TestStableStringifyRefusesNonPortableFloats(t *testing.T) {
	rejected := map[string]float64{
		"1e16":       1e16,
		"-1e16":      -1e16,
		"1e17":       1e17,
		"2^63 + eps": 1e19, // the old int64-cast overflow zone
		"0.00001":    0.00001,
		"-0.0":       math.Copysign(0, -1),
		"NaN":        math.NaN(),
		"+Inf":       math.Inf(1),
		"-Inf":       math.Inf(-1),
	}
	for name, v := range rejected {
		if got, err := StableStringify(map[string]interface{}{"x": v}); err == nil {
			t.Errorf("%s must be refused as non-portable, serialized to %s", name, got)
		}
	}

	accepted := map[float64]string{
		9999999999999998.0: `{"x":9999999999999998}`, // the vectors' f16 boundary case, just under 1e16
		0.0001:             `{"x":0.0001}`,           // the small-float boundary, inclusive
		0:                  `{"x":0}`,
		-7:                 `{"x":-7}`,
		0.5:                `{"x":0.5}`,
	}
	for v, want := range accepted {
		got, err := StableStringify(map[string]interface{}{"x": v})
		if err != nil {
			t.Errorf("%v must stay portable, got error: %v", v, err)
			continue
		}
		if got != want {
			t.Errorf("StableStringify(%v) = %s, want %s", v, got, want)
		}
	}
}

// TestStableStringifyRefusesNonPortableIntegers pins the parity point that matters for Go
// specifically: every TS number is a float64, so an int64 the TS reference would refuse must be
// refused here too — otherwise a Go relying party signs bytes no other port can ever produce.
func TestStableStringifyRefusesNonPortableIntegers(t *testing.T) {
	for name, v := range map[string]interface{}{
		"int64(1e17)":  int64(1e17),
		"int64(1e16)":  int64(1e16),
		"int64(-1e16)": int64(-1e16),
	} {
		if got, err := StableStringify(map[string]interface{}{"x": v}); err == nil {
			t.Errorf("%s must be refused as non-portable, serialized to %s", name, got)
		}
	}
	got, err := StableStringify(map[string]interface{}{"x": int64(1e16 - 1)})
	if err != nil {
		t.Fatalf("int64(1e16-1) is inside the portable range, got error: %v", err)
	}
	if want := `{"x":9999999999999999}`; got != want {
		t.Errorf("StableStringify(int64(1e16-1)) = %s, want %s", got, want)
	}
	if got, err := StableStringify(map[string]interface{}{"x": int(42)}); err != nil || got != `{"x":42}` {
		t.Errorf("StableStringify(int(42)) = %s, %v; want {\"x\":42}, nil", got, err)
	}
}

// ─── Types the canonicalizer cannot canonicalize ────────────────────────────

// TestStableStringifyRefusesUncanonicalizableGoTypes pins the fail-closed default branch. Go is the
// only port with no closed JSON value type, so a caller can hand the canonicalizer a float32, a
// uint64 or a map[string]string. This used to fall through to encoding/json, which sorts keys by
// UTF-8 bytes instead of UTF-16 code units, escapes U+2028/U+2029, and applies no portable-range
// check — the exact three contradictions of the shared vectors. The shared vector harness cannot
// reach this: it decodes every case into interface{} first, so nothing typed ever arrives.
func TestStableStringifyRefusesUncanonicalizableGoTypes(t *testing.T) {
	type approval struct{ Amount int }
	for name, v := range map[string]interface{}{
		"map[string]string": map[string]string{"a": "b"},
		"float32":           float32(1e20),
		"uint64":            uint64(20000000000000000),
		"uint":              uint(1),
		"int32":             int32(7),
		"[]int":             []int{1, 2},
		"[]float64":         []float64{1.5},
		"struct":            approval{Amount: 1},
		"json.Number":       json.Number("1"),
	} {
		got, err := StableStringify(map[string]interface{}{"x": v})
		if err == nil {
			t.Errorf("%s must be refused, serialized to %s", name, got)
			continue
		}
		if !strings.Contains(err.Error(), "cannot be canonicalized") {
			t.Errorf("%s: reason should say the value cannot be canonicalized, got: %v", name, err)
		}
	}

	// The error names the Go type, so the caller can find the offending field.
	_, err := StableStringify(map[string]interface{}{"x": uint64(1)})
	if err == nil || !strings.Contains(err.Error(), "uint64") {
		t.Errorf("the refusal must name the Go type, got: %v", err)
	}
}

// TestStableStringifyHandlesStringSlices pins the one typed shape the canonicalizer does accept:
// the builders hand allowedAaguids and delegatedTo in as []string, so it must take the same
// JS-compatible string path as everything else rather than encoding/json — which escapes
// U+2028/U+2029 unconditionally, contradicting the "line-separators" shared vector.
func TestStableStringifyHandlesStringSlices(t *testing.T) {
	got, err := StableStringify(map[string]interface{}{"tags": []string{"a b", "x&y"}})
	if err != nil {
		t.Fatalf("[]string is canonicalizable, got error: %v", err)
	}
	want := "{\"tags\":[\"a b\",\"x&y\"]}"
	if got != want {
		t.Errorf("StableStringify([]string) = %q, want %q", got, want)
	}
	// Identical bytes whichever way the caller spells the same array.
	viaInterface, err := StableStringify(map[string]interface{}{"tags": []interface{}{"a b", "x&y"}})
	if err != nil {
		t.Fatalf("[]interface{} refused: %v", err)
	}
	if viaInterface != got {
		t.Errorf("[]string and []interface{} disagree:\n  %q\n  %q", got, viaInterface)
	}
}

// TestVerifyFailsClosedOnUncanonicalizableExpectedParams pins the SHAPE of the failure at the
// relying-party boundary: Expected.Params is a map[string]interface{}, so writing []int or a uint64
// id into it is ordinary Go. It must surface as "not canonicalizable", never as the
// tampering-shaped "do not match" the silent encoding/json fallback used to produce.
func TestVerifyFailsClosedOnUncanonicalizableExpectedParams(t *testing.T) {
	requester := RequesterIdentity{DID: "did:intyga:service:agent", Attestation: nil}
	requirement := ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human"}
	approved, err := CanonicalIntentPayload(
		"prod-db", "transfer", "Transfer",
		map[string]interface{}{"ids": []interface{}{float64(1)}},
		requester, requirement, "c_uc_1", "2999-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("portable payload refused: %v", err)
	}
	res := VerifyApprovalReceipt(
		ApprovalReceipt{
			CanonicalPayload:  approved,
			ActionDescription: "Transfer",
			Params:            map[string]interface{}{"ids": []interface{}{float64(1)}},
			Requester:         &requester,
		},
		Expected{
			Target:     "prod-db",
			Nonce:      "c_uc_1",
			ActionType: "transfer",
			Params:     map[string]interface{}{"ids": []int{1}},
			Approvers:  ApproverTrustAnchor{PublicKeys: []string{"AAAA"}},
		},
		VerifyOptions{},
	)
	if res.OK {
		t.Fatal("uncanonicalizable expected params must fail closed")
	}
	if !strings.Contains(res.Reason, "not canonicalizable") {
		t.Errorf("reason should name the canonicalization failure, got: %s", res.Reason)
	}
	if strings.Contains(res.Reason, "do not match") {
		t.Errorf("reason must not be tampering-shaped, got: %s", res.Reason)
	}
}

// TestBuilderPropagatesNonPortableNumber pins that the canonical builders surface the refusal
// instead of swallowing it.
func TestBuilderPropagatesNonPortableNumber(t *testing.T) {
	requester := RequesterIdentity{DID: "did:intyga:service:deploy", Attestation: nil}
	requirement := ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human"}
	if got, err := CanonicalIntentPayload(
		"prod-db", "transfer", "Transfer",
		map[string]interface{}{"amount": 1e16},
		requester, requirement, "c_1", "2026-07-24T12:00:00Z",
	); err == nil {
		t.Fatalf("CanonicalIntentPayload must refuse a non-portable param, emitted %s", got)
	}
}

// TestVerifyFailsClosedOnNonPortableExpectedParams pins the SHAPE of the failure: a relying party
// whose own params carry a non-portable number gets a reason that says so, never the
// tampering-shaped "do not match" — the two causes need entirely different responses from an
// operator, and the TS reference makes the same distinction.
func TestVerifyFailsClosedOnNonPortableExpectedParams(t *testing.T) {
	requester := RequesterIdentity{DID: "did:intyga:service:agent", Attestation: nil}
	requirement := ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human"}
	approved, err := CanonicalIntentPayload(
		"prod-db", "transfer", "Transfer",
		map[string]interface{}{"amount": float64(9000)},
		requester, requirement, "c_np_1", "2999-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("portable payload refused: %v", err)
	}
	receipt := ApprovalReceipt{
		CanonicalPayload:  approved,
		ActionDescription: "Transfer",
		Params:            map[string]interface{}{"amount": float64(9000)},
		Requester:         &requester,
	}
	expected := Expected{
		Target:     "prod-db",
		Nonce:      "c_np_1",
		ActionType: "transfer",
		Params:     map[string]interface{}{"amount": 1e16},
		Approvers:  ApproverTrustAnchor{PublicKeys: []string{"AAAA"}},
	}
	res := VerifyApprovalReceipt(receipt, expected, VerifyOptions{})
	if res.OK {
		t.Fatal("non-portable expected params must fail closed")
	}
	if !strings.Contains(res.Reason, "not canonicalizable") {
		t.Errorf("reason should name the canonicalization failure, got: %s", res.Reason)
	}
	if strings.Contains(res.Reason, "do not match") {
		t.Errorf("reason must not be tampering-shaped for a non-portable number, got: %s", res.Reason)
	}
}

// ─── Witness DoS bounds (August 2026 audit) ─────────────────────────────────

// garbageWitnesses builds n structurally-valid witnesses that can never verify. The bound check
// runs before any crypto, so nothing here needs a real key.
func garbageWitnesses(n int) []ApprovalWitness {
	witnesses := make([]ApprovalWitness, n)
	for i := range witnesses {
		witnesses[i] = ApprovalWitness{
			SignerDID:       fmt.Sprintf("did:intyga:human:%d", i),
			SignerPublicKey: "AAAA",
			Signature:       "AAAA",
		}
	}
	return witnesses
}

// TestApprovalRefusesOversizedWitnessList pins MaxWitnesses on the approval path. The witness list
// is attacker-supplied and each entry costs ECDSA work in the relying party's own process; the TS
// reference measured a 20,000-witness receipt at 3.6s of blocked event loop before the same bound
// landed there.
func TestApprovalRefusesOversizedWitnessList(t *testing.T) {
	requester := RequesterIdentity{DID: "did:intyga:service:agent", Attestation: nil}
	requirement := ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human"}
	params := map[string]interface{}{"path": "/tmp"}
	canonical, err := CanonicalIntentPayload(
		"sandbox-cluster", "listFiles", "List files", params,
		requester, requirement, "c_bound_1", "2999-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("portable payload refused: %v", err)
	}
	receipt := ApprovalReceipt{
		CanonicalPayload:  canonical,
		ActionDescription: "List files",
		Params:            params,
		Signatures:        garbageWitnesses(MaxWitnesses + 1),
		Requester:         &requester,
	}
	expected := Expected{
		Target:     "sandbox-cluster",
		Nonce:      "c_bound_1",
		ActionType: "listFiles",
		Params:     params,
		Approvers:  ApproverTrustAnchor{PublicKeys: []string{"AAAA"}},
	}
	res := VerifyApprovalReceipt(receipt, expected, VerifyOptions{})
	if res.OK {
		t.Fatal("a receipt above MaxWitnesses must be refused")
	}
	if !strings.Contains(res.Reason, fmt.Sprintf("%d witnesses", MaxWitnesses+1)) {
		t.Errorf("reason should name the oversized witness count, got: %s", res.Reason)
	}
}

// TestDelegationRefusesOversizedWitnessList pins the same bound on the delegation path, which has
// its own witness loop.
func TestDelegationRefusesOversizedWitnessList(t *testing.T) {
	requester := RequesterIdentity{DID: "did:intyga:service:pipeline", Attestation: nil}
	requirement := ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human"}
	params := map[string]interface{}{"environment": "prod"}
	delegates := []string{"did:intyga:human:alice", "did:intyga:human:bob"}
	canonical, err := CanonicalDelegationPayload(
		"prod-db", "deleteDatabase", "Drop prod", params, requester, requirement,
		delegates, 1, "c_bound_2", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("portable payload refused: %v", err)
	}
	receipt := ApprovalReceipt{
		CanonicalPayload:  canonical,
		ActionDescription: "Drop prod",
		Params:            params,
		Signatures:        garbageWitnesses(MaxWitnesses + 1),
		Requester:         &requester,
	}
	expected := Expected{
		Target:     "prod-db",
		ActionType: "deleteDatabase",
		Params:     params,
		// DID mode: delegations refuse a key-set anchor outright (DIV §4.4.6), and this test is
		// about the witness cap, which must still be reached.
		Approvers: ApproverTrustAnchor{
			DIDs:       []string{"did:intyga:human:alice"},
			ResolveKey: func(did string) string { return "AAAA" },
		},
	}
	res, delegation := VerifyDelegation(receipt, expected, VerifyOptions{AllowExpired: true})
	if res.OK || delegation != nil {
		t.Fatal("a delegation above MaxWitnesses must be refused")
	}
	if !strings.Contains(res.Reason, fmt.Sprintf("%d witnesses", MaxWitnesses+1)) {
		t.Errorf("reason should name the oversized witness count, got: %s", res.Reason)
	}
}

// TestQuorumFailureReasonStaysBounded pins the failure fold: a full MaxWitnesses list of garbage
// (inside the bound, so every witness is examined and fails) must produce a Reason that reports at
// most maxReportedFailures entries plus a "+N more" suffix — not the megabyte of error text the
// unbounded join produced in the TS reference.
func TestQuorumFailureReasonStaysBounded(t *testing.T) {
	requester := RequesterIdentity{DID: "did:intyga:service:agent", Attestation: nil}
	requirement := ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human"}
	params := map[string]interface{}{"path": "/tmp"}
	canonical, err := CanonicalIntentPayload(
		"sandbox-cluster", "listFiles", "List files", params,
		requester, requirement, "c_bound_3", "2999-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("portable payload refused: %v", err)
	}
	receipt := ApprovalReceipt{
		CanonicalPayload:  canonical,
		ActionDescription: "List files",
		Params:            params,
		Signatures:        garbageWitnesses(MaxWitnesses),
		Requester:         &requester,
	}
	expected := Expected{
		Target:     "sandbox-cluster",
		Nonce:      "c_bound_3",
		ActionType: "listFiles",
		Params:     params,
		Approvers:  ApproverTrustAnchor{PublicKeys: []string{"AAAA"}},
	}
	res := VerifyApprovalReceipt(receipt, expected, VerifyOptions{})
	if res.OK {
		t.Fatal("garbage witnesses must not satisfy a quorum")
	}
	if !strings.Contains(res.Reason, "quorum not met") {
		t.Fatalf("expected a quorum failure, got: %s", res.Reason)
	}
	elided := MaxWitnesses - maxReportedFailures
	if !strings.Contains(res.Reason, fmt.Sprintf("; +%d more", elided)) {
		t.Errorf("expected %d elided failures to be summarized, got: %s", elided, res.Reason)
	}
	if len(res.Reason) > 1000 {
		t.Errorf("failure reason is not bounded: %d bytes", len(res.Reason))
	}
}

// TestSignerClassRegistryFailsClosed pins DIV §4.3.2 / §5-step-3a: a payload whose signerClass is
// absent or unrecognized must never verify — an unknown class treated as human-equivalent would
// make "human-approved" an unverifiable claim the moment a second class exists.
func TestSignerClassRegistryFailsClosed(t *testing.T) {
	autoApproved := "AUTO_APPROVED"
	requester := RequesterIdentity{DID: "did:intyga:service:agent", Attestation: nil}
	expected := Expected{
		Target:     "sandbox-cluster",
		Nonce:      "c_nonce_sc",
		ActionType: "listFiles",
		Params:     map[string]interface{}{"path": "/tmp"},
		Approvers:  ApproverTrustAnchor{PublicKeys: []string{}},
	}
	// AUTO_APPROVED with AllowAutoApproved+AllowExpired is the minimal path that would otherwise
	// verify with no signature material, so a pass here isolates the signerClass gate itself.
	opts := VerifyOptions{AllowAutoApproved: true, AllowExpired: true}

	for _, tc := range []struct {
		name        string
		signerClass string
		wantReason  string
	}{
		{"unrecognized class refused", "delegated-agent", "does not recognize"},
		{"absent class refused", "", "missing signerClass"},
	} {
		requirement := ApprovalRequirement{RequiredApprovals: 1, SignerClass: tc.signerClass}
		canonical, err := CanonicalIntentPayload(
			"sandbox-cluster", "listFiles", "List files",
			map[string]interface{}{"path": "/tmp"},
			requester, requirement, "c_nonce_sc", "2999-01-01T00:00:00Z",
		)
		if err != nil {
			t.Fatalf("%s: CanonicalIntentPayload refused portable input: %v", tc.name, err)
		}
		receipt := ApprovalReceipt{
			CanonicalPayload:  canonical,
			ActionDescription: "List files",
			Params:            map[string]interface{}{"path": "/tmp"},
			SigAlg:            &autoApproved,
			Requester:         &requester,
		}
		r := VerifyApprovalReceipt(receipt, expected, opts)
		if r.OK {
			t.Fatalf("%s: verified despite signerClass %q", tc.name, tc.signerClass)
		}
		if !strings.Contains(r.Reason, tc.wantReason) {
			t.Fatalf("%s: refused for the wrong reason: %s", tc.name, r.Reason)
		}
	}
}

// TestDelegationRefusesKeySetAnchor pins DIV §4.4.6 at SEAL verification: the sealing quorum names
// people, so a PublicKeys anchor (credentials-as-identities) must be refused outright — previously
// only delegatedTo enforcement at use time refused it.
func TestDelegationRefusesKeySetAnchor(t *testing.T) {
	res, _ := VerifyDelegation(
		ApprovalReceipt{CanonicalPayload: `{"v":1,"type":"div-delegation"}`},
		Expected{Approvers: ApproverTrustAnchor{PublicKeys: []string{"a-listed-key"}}},
		VerifyOptions{},
	)
	if res.OK {
		t.Fatal("delegation under a key-set anchor must be refused")
	}
	if !strings.Contains(res.Reason, "§4.4.6") {
		t.Fatalf("wrong reason: %s", res.Reason)
	}
}
