package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExtendedCanonicalVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("vectors", "canonical-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		AgentIntents []struct {
			Input struct {
				Target, ActionType, ActionDescription, Nonce, ExpiresAt string
				Params                                                  map[string]interface{}
				Requester                                               RequesterIdentity
				Requirement                                             ApprovalRequirement
				AgentContext                                            map[string]interface{}
			}
			Expected string
		} `json:"agentIntentPayloads"`
		Agent []struct {
			Input struct {
				Target, Nonce, ActionDescription, AgentDID, SealedAt, ExpiresAt string
				ActionPatterns                                                  []string
				ParentReceiptHash                                               string
				Requester                                                       RequesterIdentity
				Requirement                                                     ApprovalRequirement
			}
			Expected string
		} `json:"agentAuthorityPayloads"`
		Platform struct {
			Cases []struct {
				Input struct {
					PayloadHash                string `json:"payloadHash"`
					RpID                       string `json:"rpId"`
					SubjectExternalID          string `json:"subjectExternalId"`
					SignedAt, ExpiresAt, Nonce string
				}
				Expected string
			}
		} `json:"platformIntentPayloads"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Agent) == 0 || len(doc.Platform.Cases) == 0 {
		t.Fatal("extended canonical vectors absent")
	}
	for _, c := range doc.AgentIntents {
		got, e := CanonicalAgentIntentPayload(c.Input.Target, c.Input.ActionType, c.Input.ActionDescription,
			c.Input.Params, c.Input.Requester, c.Input.Requirement, c.Input.Nonce, c.Input.ExpiresAt, c.Input.AgentContext)
		if e != nil || got != c.Expected {
			t.Fatalf("agent intent canonical drift: %v\n%s\n%s", e, got, c.Expected)
		}
	}
	for _, c := range doc.Agent {
		got, e := CanonicalAgentAuthorityPayload(c.Input.Target, c.Input.ActionPatterns, c.Input.ActionDescription, c.Input.AgentDID, c.Input.Requester, c.Input.Requirement, c.Input.Nonce, c.Input.SealedAt, c.Input.ExpiresAt, c.Input.ParentReceiptHash)
		if e != nil || got != c.Expected {
			t.Fatalf("agent authority canonical drift: %v\n%s\n%s", e, got, c.Expected)
		}
	}
	for _, c := range doc.Platform.Cases {
		got, e := CanonicalPlatformIntentPayload(c.Input.PayloadHash, c.Input.RpID, c.Input.SubjectExternalID, c.Input.SignedAt, c.Input.ExpiresAt, c.Input.Nonce)
		if e != nil || got != c.Expected {
			t.Fatalf("platform canonical drift: %v\n%s\n%s", e, got, c.Expected)
		}
	}
}
