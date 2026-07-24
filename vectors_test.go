package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
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
		if sigAlg == "WEBAUTHN" || (sigAlg != "AUTO_APPROVED" && canonicalVersion(canonical) != 3) {
			continue
		}

		actionType := ""
		if entry.Receipt.ActionType != nil {
			actionType = *entry.Receipt.ActionType
		}
		expected := Expected{
			Nonce:      canonicalNonce(canonical),
			ActionType: actionType,
			Params:     entry.Receipt.Params,
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
