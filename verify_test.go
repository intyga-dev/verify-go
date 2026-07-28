package verify

import (
	"testing"
)

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
	}

	got := CanonicalIntentPayload("prod-db-cluster-01", "deleteDatabase", "Delete staging database", params, req, requirement, "c_8f91a2", "2026-07-23T19:30:00Z")
	// Strict RFC 8785 JCS: every key sorted; type/version last. Byte-for-byte the string the TS
	// reference implementation (@intyga/mcp-schemas) emits for the same input.
	expected := `{"actionType":"deleteDatabase","display":"Delete staging database","expiresAt":"2026-07-23T19:30:00Z","nonce":"c_8f91a2","params":{"alpha":2,"mid":{"a":2,"z":1},"zeta":1},"requester":{"attestation":null,"did":"did:intyga:service:deploy-pipeline"},"requirement":{"allowedAaguids":["a-aaguid","b-aaguid"],"requesterCannotApprove":true,"requireHardwareKey":true,"requiredApprovals":2},"target":"prod-db-cluster-01","type":"div-intent-verification","v":1}`

	if got != expected {
		t.Fatalf("CanonicalIntentPayload mismatch:\nGot:  %s\nWant: %s", got, expected)
	}
}
