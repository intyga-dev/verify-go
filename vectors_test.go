package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenDoc mirrors the parts of packages/mcp-schemas/vectors/canonical-vectors.json we consume.
type goldenDoc struct {
	Receipts []struct {
		Name     string          `json:"name"`
		Receipt  ApprovalReceipt `json:"receipt"`
		ExpectOK bool            `json:"expectOk"`
	} `json:"receipts"`
}

// canonicalVersion reads the "v" field out of a canonical payload; 0 if unparseable.
func canonicalVersion(canonical string) int {
	var probe struct {
		V int `json:"v"`
	}
	_ = json.Unmarshal([]byte(canonical), &probe)
	return probe.V
}

// canonicalNonce reads the "nonce" field out of a canonical payload.
func canonicalNonce(canonical string) string {
	var probe struct {
		Nonce string `json:"nonce"`
	}
	_ = json.Unmarshal([]byte(canonical), &probe)
	return probe.Nonce
}

// TestSharedGoldenReceiptVectors drives the current-version receipts from the shared
// cross-language golden vectors — the same file the Python and TS suites consume — so all
// languages stay byte-identical. Legacy v2 and WebAuthn vectors are skipped (WebAuthn is
// exercised separately); the verifier targets the single current canonical version.
func TestSharedGoldenReceiptVectors(t *testing.T) {
	path := filepath.Join("vectors", "canonical-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden vectors: %v", err)
	}
	var doc goldenDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse golden vectors: %v", err)
	}

	checked := 0
	for _, entry := range doc.Receipts {
		sigAlg := ""
		if entry.Receipt.SigAlg != nil {
			sigAlg = *entry.Receipt.SigAlg
		}
		canonical := entry.Receipt.CanonicalPayload
		if sigAlg == "WEBAUTHN" || (sigAlg != "AUTO_APPROVED" && canonicalVersion(canonical) != DivVersion) {
			continue
		}

		actionType := ""
		if entry.Receipt.ActionType != nil {
			actionType = *entry.Receipt.ActionType
		}
		target := ""
		if entry.Receipt.Target != nil {
			target = *entry.Receipt.Target
		}
		// See the note in webauthn_test.go: for a golden vector, the committed signer key is the
		// out-of-band enrollment record the relying party would resolve for itself.
		signerKey := ""
		if entry.Receipt.SignerPublicKey != nil {
			signerKey = *entry.Receipt.SignerPublicKey
		}
		expected := Expected{
			Target:     target,
			Nonce:      canonicalNonce(canonical),
			ActionType: actionType,
			Params:     entry.Receipt.Params,
			Approvers:  ApproverTrustAnchor{PublicKeys: []string{signerKey}},
		}

		result := VerifyApprovalReceipt(entry.Receipt, expected, VerifyOptions{})
		if result.OK != entry.ExpectOK {
			t.Errorf("vector %q: expected ok=%v but got ok=%v (reason=%q)",
				entry.Name, entry.ExpectOK, result.OK, result.Reason)
		}
		checked++
	}
	if checked < 3 {
		t.Fatalf("expected to exercise the current-version vectors, ran %d", checked)
	}
}

// offlineDoc mirrors the offline-approval and delegation halves of the golden vectors.
type offlineDoc struct {
	OfflineIntentPayloads []struct {
		Input struct {
			Target            string                 `json:"target"`
			Nonce             string                 `json:"nonce"`
			ActionType        string                 `json:"actionType"`
			ActionDescription string                 `json:"actionDescription"`
			Params            map[string]interface{} `json:"params"`
			Requester         RequesterIdentity      `json:"requester"`
			Requirement       ApprovalRequirement    `json:"requirement"`
			ChallengedAt      string                 `json:"challengedAt"`
			ExpiresAt         string                 `json:"expiresAt"`
		} `json:"input"`
		Expected string `json:"expected"`
	} `json:"offlineIntentPayloads"`
	DelegationPayloads []struct {
		Input struct {
			Target            string                 `json:"target"`
			Nonce             string                 `json:"nonce"`
			ActionType        string                 `json:"actionType"`
			ActionDescription string                 `json:"actionDescription"`
			Params            map[string]interface{} `json:"params"`
			Requester         RequesterIdentity      `json:"requester"`
			Requirement       ApprovalRequirement    `json:"requirement"`
			DelegatedTo       []string               `json:"delegatedTo"`
			DelegatedQuorum   int                    `json:"delegatedQuorum"`
			SealedAt          string                 `json:"sealedAt"`
			ExpiresAt         string                 `json:"expiresAt"`
		} `json:"input"`
		Expected string `json:"expected"`
	} `json:"delegationPayloads"`
}

func loadOfflineDoc(t *testing.T) offlineDoc {
	t.Helper()
	path := filepath.Join("vectors", "canonical-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden vectors: %v", err)
	}
	var doc offlineDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse golden vectors: %v", err)
	}
	return doc
}

// TestOfflineCanonicalParity pins the OFFLINE APPROVAL canonicalization against the shared vectors.
//
// The receipts test above exercises verification; this one pins the byte output, which is where a port
// silently diverges. A Go build emitting different bytes could not verify an approval any TypeScript
// relying party produced — and the failure would look like tampering rather than drift.
func TestOfflineCanonicalParity(t *testing.T) {
	doc := loadOfflineDoc(t)
	if len(doc.OfflineIntentPayloads) == 0 {
		t.Fatal("no offline-approval vectors present")
	}
	for _, c := range doc.OfflineIntentPayloads {
		got := CanonicalOfflineIntentPayload(
			c.Input.Target,
			c.Input.ActionType,
			c.Input.ActionDescription,
			c.Input.Params,
			c.Input.Requester,
			c.Input.Requirement,
			c.Input.Nonce,
			c.Input.ChallengedAt,
			c.Input.ExpiresAt,
		)
		if got != c.Expected {
			t.Errorf("offline vector drift for %s:\n got  %s\n want %s", c.Input.ActionType, got, c.Expected)
		}
		if !strings.Contains(got, `"type":"div-offline-intent"`) {
			t.Errorf("payload for %s is missing the offline type discriminator", c.Input.ActionType)
		}
	}
}

// TestDelegationCanonicalParity pins the DELEGATION canonicalization, including that delegatedTo is
// canonicalized as a SET. The vector input is deliberately unsorted, so this is what proves the sort.
func TestDelegationCanonicalParity(t *testing.T) {
	doc := loadOfflineDoc(t)
	if len(doc.DelegationPayloads) == 0 {
		t.Fatal("no delegation vectors present")
	}
	for _, c := range doc.DelegationPayloads {
		got := CanonicalDelegationPayload(
			c.Input.Target,
			c.Input.ActionType,
			c.Input.ActionDescription,
			c.Input.Params,
			c.Input.Requester,
			c.Input.Requirement,
			c.Input.DelegatedTo,
			c.Input.DelegatedQuorum,
			c.Input.Nonce,
			c.Input.SealedAt,
			c.Input.ExpiresAt,
		)
		if got != c.Expected {
			t.Errorf("delegation vector drift for %s:\n got  %s\n want %s", c.Input.ActionType, got, c.Expected)
		}
		if !strings.Contains(got, `"type":"div-delegation"`) {
			t.Errorf("payload for %s is missing the delegation type discriminator", c.Input.ActionType)
		}
		if !strings.Contains(got, `"delegatedTo":["did:intyga:sre-a","did:intyga:sre-b","did:intyga:sre-c"]`) {
			t.Errorf("delegatedTo was not canonicalized as a sorted set for %s: %s", c.Input.ActionType, got)
		}
	}
}

// TestOfflineKindsNeverCollide pins the property that matters more than parity: the payload kinds must
// never produce the same bytes for the same action. If they could, an out-of-band approval would be
// indistinguishable from a gateway-mediated one, and an ordinary approval could be replayed as offline.
func TestOfflineKindsNeverCollide(t *testing.T) {
	doc := loadOfflineDoc(t)
	for _, c := range doc.OfflineIntentPayloads {
		offline := CanonicalOfflineIntentPayload(
			c.Input.Target, c.Input.ActionType, c.Input.ActionDescription, c.Input.Params,
			c.Input.Requester, c.Input.Requirement, c.Input.Nonce, c.Input.ChallengedAt, c.Input.ExpiresAt,
		)
		intent := CanonicalIntentPayload(
			c.Input.Target, c.Input.ActionType, c.Input.ActionDescription, c.Input.Params,
			c.Input.Requester, c.Input.Requirement, c.Input.Nonce, c.Input.ExpiresAt,
		)
		if offline == intent {
			t.Errorf("offline and intent payloads collide for %s", c.Input.ActionType)
		}
	}
}
