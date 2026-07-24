package verify

import (
	"testing"
)

func TestCanonicalAuthorizationPayloadV3Parity(t *testing.T) {
	params := map[string]interface{}{
		"zeta":  float64(1),
		"alpha": float64(2),
		"mid": map[string]interface{}{
			"z": float64(1),
			"a": float64(2),
		},
	}
	req := RequesterIdentity{
		DID:         "did:sakra:service:deploy-pipeline",
		Attestation: nil,
	}

	exp := "2026-07-23T19:30:00Z"
	got := CanonicalAuthorizationPayloadV3("c_8f91a2", "deleteDatabase", "Delete staging database", params, req, &exp)
	expected := `{"v":3,"type":"agent-authorization","nonce":"c_8f91a2","actionType":"deleteDatabase","action":"Delete staging database","params":{"alpha":2,"mid":{"a":2,"z":1},"zeta":1},"requester":{"did":"did:sakra:service:deploy-pipeline","attestation":null},"expiresAt":"2026-07-23T19:30:00Z"}`

	if got != expected {
		t.Fatalf("CanonicalAuthorizationPayloadV3 mismatch:\nGot:  %s\nWant: %s", got, expected)
	}
}
