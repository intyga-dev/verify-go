package verify

import (
	"encoding/json"
	"testing"
)

// DIV §4.3.2: present-but-null is malformed, not absent. encoding/json alone reads both as nil.
func TestPresentNullIdentityExtensionsAreRefusedNotDropped(t *testing.T) {
	var nullIssuer, absentIssuer RequesterIdentity
	if err := json.Unmarshal([]byte(`{"did":"did:r","attestation":null,"credentialIssuerDid":null}`), &nullIssuer); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"did":"did:r","attestation":null}`), &absentIssuer); err != nil {
		t.Fatal(err)
	}
	base := `{"requiredApprovals":1,"requireHardwareKey":false,"allowedAaguids":[],"requesterCannotApprove":false,"signerClass":"human"`
	var nullExclusions, absentExclusions ApprovalRequirement
	if err := json.Unmarshal([]byte(base+`,"excludedSignerDids":null}`), &nullExclusions); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(base+`}`), &absentExclusions); err != nil {
		t.Fatal(err)
	}

	if ok, reason := checkExcludedSigners(absentExclusions, nullIssuer); ok || reason != "signed requester.credentialIssuerDid must be a non-empty DID" {
		t.Fatalf("null issuer: ok=%v reason=%q", ok, reason)
	}
	if ok, reason := checkExcludedSigners(nullExclusions, absentIssuer); ok || reason != "signed requirement.excludedSignerDids must be an array of valid DIDs" {
		t.Fatalf("null exclusions: ok=%v reason=%q", ok, reason)
	}
	if ok, reason := checkExcludedSigners(absentExclusions, absentIssuer); !ok {
		t.Fatalf("absent extensions must stay valid: %q", reason)
	}

	if _, err := CanonicalIntentPayload("t", "a", "d", map[string]interface{}{}, nullIssuer, absentExclusions, "n", "2027-01-01T00:00:00.000Z"); err == nil || err.Error() != "credentialIssuerDid must be a valid DID" {
		t.Fatalf("builder accepted a null issuer: %v", err)
	}
	if _, err := CanonicalIntentPayload("t", "a", "d", map[string]interface{}{}, absentIssuer, nullExclusions, "n", "2027-01-01T00:00:00.000Z"); err == nil || err.Error() != "excludedSignerDids must be a DID array" {
		t.Fatalf("builder accepted null exclusions: %v", err)
	}
}
