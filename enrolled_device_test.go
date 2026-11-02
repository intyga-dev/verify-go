package verify

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// DIV §4.3.2 "Enrolled approver devices". The shared vectors (enrolledDevice section) pin the
// verdicts and texts; these tests pin the Go-specific modelling: absent versus present-false or
// present-null, the builders' refusals, and the floor's JSON decoding.

const enrolledBase = `{"requiredApprovals":1,"requireHardwareKey":false,"allowedAaguids":[],"requesterCannotApprove":false,"signerClass":"human"`

func parseEnrolledRequirement(t *testing.T, extra string) ApprovalRequirement {
	t.Helper()
	var r ApprovalRequirement
	if err := json.Unmarshal([]byte(enrolledBase+extra+`}`), &r); err != nil {
		t.Fatalf("%s: %v", extra, err)
	}
	return r
}

func TestRequireEnrolledDeviceParsingDistinguishesAbsentFromPresentNotTrue(t *testing.T) {
	if why := enrolledDeviceStructureProblem(parseEnrolledRequirement(t, ""), true); why != "" {
		t.Fatalf("absent must be valid: %s", why)
	}
	if r := parseEnrolledRequirement(t, `,"requireEnrolledDevice":true`); !r.RequireEnrolledDevice || enrolledDeviceStructureProblem(r, true) != "" {
		t.Fatalf("present true must parse and be valid on an ordinary intent")
	}
	for _, bad := range []string{`false`, `null`, `"true"`, `1`, `{}`} {
		r := parseEnrolledRequirement(t, `,"requireEnrolledDevice":`+bad)
		if r.RequireEnrolledDevice {
			t.Fatalf("%s must not read as true", bad)
		}
		if why := enrolledDeviceStructureProblem(r, true); why != EnrolledDeviceMalformedReason {
			t.Fatalf("%s: %q", bad, why)
		}
		// Malformed wins over the payload-kind rule, as in the reference.
		if why := enrolledDeviceStructureProblem(r, false); why != EnrolledDeviceMalformedReason {
			t.Fatalf("%s on a non-ordinary kind: %q", bad, why)
		}
	}
	if why := enrolledDeviceStructureProblem(parseEnrolledRequirement(t, `,"requireEnrolledDevice":true`), false); why != EnrolledDeviceOrdinaryOnlyReason {
		t.Fatalf("non-ordinary: %q", why)
	}
	var hw ApprovalRequirement
	if err := json.Unmarshal([]byte(`{"requiredApprovals":1,"requireHardwareKey":true,"allowedAaguids":[],"requesterCannotApprove":false,"signerClass":"human","requireEnrolledDevice":true}`), &hw); err != nil {
		t.Fatal(err)
	}
	if why := enrolledDeviceStructureProblem(hw, true); why != EnrolledDeviceWithHardwareReason {
		t.Fatalf("hardware combination: %q", why)
	}
	// Re-decoding into a used struct must not keep an earlier verdict.
	r := parseEnrolledRequirement(t, `,"requireEnrolledDevice":false`)
	if err := json.Unmarshal([]byte(enrolledBase+`}`), &r); err != nil {
		t.Fatal(err)
	}
	if enrolledDeviceStructureProblem(r, true) != "" {
		t.Fatalf("stale malformed flag survived a re-decode")
	}
}

func TestRequireEnrolledDeviceBuilders(t *testing.T) {
	requester := RequesterIdentity{DID: "did:ex:agent"}
	params := map[string]interface{}{"ref": "1"}
	device := ApprovalRequirement{RequiredApprovals: 1, AllowedAaguids: []string{}, SignerClass: "human", RequireEnrolledDevice: true}
	plain := ApprovalRequirement{RequiredApprovals: 1, AllowedAaguids: []string{}, SignerClass: "human"}

	got, err := CanonicalIntentPayload("t", "a", "d", params, requester, device, "n", "2999-01-01T00:00:00.000Z")
	if err != nil || !strings.Contains(got, `"requireEnrolledDevice":true`) {
		t.Fatalf("ordinary intent must serialize the literal true: %v %s", err, got)
	}
	got, err = CanonicalIntentPayload("t", "a", "d", params, requester, plain, "n", "2999-01-01T00:00:00.000Z")
	if err != nil || strings.Contains(got, "requireEnrolledDevice") {
		t.Fatalf("false must be omitted, never serialized: %v %s", err, got)
	}
	context := map[string]interface{}{
		"action":  map[string]interface{}{"reversibility": "reversible"},
		"agent":   map[string]interface{}{"did": "did:ex:agent"},
		"session": map[string]interface{}{"id": "s"},
		"nbf":     "2026-01-01T00:00:00.000Z",
	}
	if _, err := CanonicalAgentIntentPayload("t", "a", "d", params, requester, device, "n", "2999-01-01T00:00:00.000Z", context); err != nil && strings.Contains(err.Error(), "requireEnrolledDevice") {
		t.Fatalf("an agent intent is a div-intent-verification payload and may carry the field: %v", err)
	}
	if _, err := CanonicalOfflineIntentPayload("t", "a", "d", params, requester, device, "n", "2026-01-01T00:00:00.000Z", "2026-01-01T00:10:00.000Z"); err == nil || err.Error() != EnrolledDeviceOrdinaryOnlyReason {
		t.Fatalf("offline builder: %v", err)
	}
	if _, err := CanonicalDelegationPayload("t", "a", "d", params, requester, device, []string{"did:ex:op"}, 1, "n", "2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.000Z"); err == nil || err.Error() != EnrolledDeviceOrdinaryOnlyReason {
		t.Fatalf("delegation builder: %v", err)
	}
	if _, err := CanonicalAgentAuthorityPayload("t", []string{"x.*"}, "d", "did:ex:agent", requester, device, "n", "2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.000Z"); err == nil || err.Error() != EnrolledDeviceOrdinaryOnlyReason {
		t.Fatalf("agent authority builder: %v", err)
	}
	hardware := device
	hardware.RequireHardwareKey = true
	aaguids := device
	aaguids.AllowedAaguids = []string{"00000000-0000-0000-0000-000000000001"}
	for name, r := range map[string]ApprovalRequirement{"hardware": hardware, "aaguids": aaguids} {
		if _, err := CanonicalIntentPayload("t", "a", "d", params, requester, r, "n", "2999-01-01T00:00:00.000Z"); err == nil || err.Error() != EnrolledDeviceWithHardwareReason {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestRequirementFloorJSONFlagsFailClosed(t *testing.T) {
	signed := ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human", RequireEnrolledDevice: true}
	for _, bad := range []string{`"yes"`, `null`, `1`} {
		for _, key := range []string{"requesterCannotApprove", "requireHardwareKey", "requireEnrolledDevice"} {
			var f RequirementFloor
			if err := json.Unmarshal([]byte(`{"requiredApprovals":1,"`+key+`":`+bad+`}`), &f); err != nil {
				t.Fatalf("%s=%s: %v", key, bad, err)
			}
			ok, reason := checkRequirementFloor(signed, &f)
			if ok || !strings.HasPrefix(reason, "expected.Requirement is malformed") {
				t.Fatalf("%s=%s: ok=%v %q", key, bad, ok, reason)
			}
		}
	}
	var f RequirementFloor
	if err := json.Unmarshal([]byte(`{"requiredApprovals":1,"requireEnrolledDevice":true}`), &f); err != nil || !f.RequireEnrolledDevice {
		t.Fatalf("decode: %v %+v", err, f)
	}
	if ok, reason := checkRequirementFloor(signed, &f); !ok {
		t.Fatalf("equal floor: %s", reason)
	}
	signed.RequireEnrolledDevice = false
	if ok, reason := checkRequirementFloor(signed, &f); ok || reason != WeakerRequirementReason+": it does not require an enrolled approver device (DIV §5 step 3d)" {
		t.Fatalf("downgrade: ok=%v %q", ok, reason)
	}
}

// coseOf hand-encodes a P-256 SPKI key as a COSE_Key: {1:2, 3:-7, -1:1, -2:x, -3:y}.
func coseOf(t *testing.T, spkiB64 string) string {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := parseSpkiP256(der)
	if err != nil {
		t.Fatal(err)
	}
	x, y := make([]byte, 32), make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	buf := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	buf = append(buf, x...)
	buf = append(buf, 0x22, 0x58, 0x20)
	buf = append(buf, y...)
	return base64.StdEncoding.EncodeToString(buf)
}

func TestEnrolledDeviceKeysCompareByPublicKeyNotEncoding(t *testing.T) {
	people, anchor, _ := floorFixture(t)
	requester := RequesterIdentity{DID: "did:ex:agent"}
	params := map[string]interface{}{"amount": 7}
	requirement := ApprovalRequirement{RequiredApprovals: 1, AllowedAaguids: []string{}, SignerClass: "human", RequireEnrolledDevice: true}
	canonical, err := CanonicalIntentPayload("prod", "payments.wire", "Wire", params, requester, requirement, "ed_nonce", "2999-01-01T00:00:00.000Z")
	if err != nil {
		t.Fatal(err)
	}
	receipt := signFloorReceipt(t, people, canonical, "Wire", params, requester, "did:ex:bob")
	expected := Expected{Target: "prod", Nonce: "ed_nonce", ActionType: "payments.wire", Params: params, Approvers: anchor}

	if r := VerifyApprovalReceipt(receipt, expected, VerifyOptions{}); r.OK || r.Reason != EnrolledDeviceKeysRequiredReason {
		t.Fatalf("nil list: %v %q", r.OK, r.Reason)
	}
	expected.EnrolledDeviceKeys = []string{}
	if r := VerifyApprovalReceipt(receipt, expected, VerifyOptions{}); r.OK || r.Reason != EnrolledDeviceKeysRequiredReason {
		t.Fatalf("empty list: %v %q", r.OK, r.Reason)
	}
	expected.EnrolledDeviceKeys = []string{people["did:ex:bob"].spki, ""}
	if r := VerifyApprovalReceipt(receipt, expected, VerifyOptions{}); r.OK || r.Reason != EnrolledDeviceKeysMalformedReason {
		t.Fatalf("empty entry: %v %q", r.OK, r.Reason)
	}
	// The anchor trusts the SPKI spelling; the enrollment record lists the COSE spelling of one key.
	expected.EnrolledDeviceKeys = []string{coseOf(t, people["did:ex:bob"].spki)}
	if r := VerifyApprovalReceipt(receipt, expected, VerifyOptions{}); !r.OK {
		t.Fatalf("COSE-listed enrolled key must match its SPKI-trusted twin: %s", r.Reason)
	}
	expected.EnrolledDeviceKeys = []string{people["did:ex:carol"].spki}
	r := VerifyApprovalReceipt(receipt, expected, VerifyOptions{})
	if r.OK || !strings.Contains(r.Reason, "signer did:ex:bob did not sign with an enrolled approver device key, but the signed policy requires one") {
		t.Fatalf("unlisted key: %v %q", r.OK, r.Reason)
	}
}
