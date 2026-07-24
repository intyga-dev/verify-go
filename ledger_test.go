package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Drives the shared cross-language DEWP ledger vectors (same file the TS/Python/Rust suites consume),
// so every language's ledger verifier stays byte-identical.
type ledgerVectors struct {
	HashLeaf []struct {
		Input    string `json:"input"`
		Expected string `json:"expected"`
	} `json:"hashLeaf"`
	HashPair []struct {
		Left     string `json:"left"`
		Right    string `json:"right"`
		Expected string `json:"expected"`
	} `json:"hashPair"`
	Sha256Hex []struct {
		Input    string `json:"input"`
		Expected string `json:"expected"`
	} `json:"sha256Hex"`
	EmptyRoot   string `json:"emptyRoot"`
	MerkleRoots []struct {
		Name     string   `json:"name"`
		Leaves   []string `json:"leaves"`
		Expected string   `json:"expected"`
	} `json:"merkleRoots"`
	LeafPreimage []struct {
		Name      string    `json:"name"`
		Row       AuditLeaf `json:"row"`
		Canonical string    `json:"canonical"`
		LeafHash  string    `json:"leafHash"`
	} `json:"leafPreimage"`
	Inclusion struct {
		Leaf            string            `json:"leaf"`
		BlockIndex      string            `json:"blockIndex"`
		BlockRoot       string            `json:"blockRoot"`
		BlockProof      []LedgerProofStep `json:"blockProof"`
		CheckpointProof []LedgerProofStep `json:"checkpointProof"`
		DailyRoot       string            `json:"dailyRoot"`
	} `json:"inclusion"`
	Anchor struct {
		Input     AnchorInput `json:"input"`
		DigestHex string      `json:"digestHex"`
	} `json:"anchor"`
}

func loadLedgerVectors(t *testing.T) ledgerVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("vectors", "ledger-vectors.json"))
	if err != nil {
		t.Fatalf("read ledger vectors: %v", err)
	}
	var v ledgerVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse ledger vectors: %v", err)
	}
	return v
}

func TestLedgerPrimitives(t *testing.T) {
	v := loadLedgerVectors(t)
	for _, c := range v.Sha256Hex {
		if got := ledgerSha256Hex([]byte(c.Input)); got != c.Expected {
			t.Errorf("sha256Hex(%q) = %s, want %s", c.Input, got, c.Expected)
		}
	}
	for _, c := range v.HashLeaf {
		if got := HashLeaf(c.Input); got != c.Expected {
			t.Errorf("HashLeaf(%q) = %s, want %s", c.Input, got, c.Expected)
		}
	}
	for _, c := range v.HashPair {
		if got := HashPair(c.Left, c.Right); got != c.Expected {
			t.Errorf("HashPair mismatch: got %s want %s", got, c.Expected)
		}
	}
	if got := EmptyRoot(); got != v.EmptyRoot {
		t.Errorf("EmptyRoot() = %s, want %s", got, v.EmptyRoot)
	}
	for _, c := range v.MerkleRoots {
		if got := MerkleRoot(c.Leaves); got != c.Expected {
			t.Errorf("MerkleRoot[%s] = %s, want %s", c.Name, got, c.Expected)
		}
	}
}

func TestLedgerLeafPreimage(t *testing.T) {
	v := loadLedgerVectors(t)
	for _, c := range v.LeafPreimage {
		if got := CanonicalPreimage(c.Row); got != c.Canonical {
			t.Errorf("CanonicalPreimage[%s] =\n  %s\nwant\n  %s", c.Name, got, c.Canonical)
		}
		if got := LeafHash(c.Row); got != c.LeafHash {
			t.Errorf("LeafHash[%s] = %s, want %s", c.Name, got, c.LeafHash)
		}
	}
}

func TestLedgerInclusionAndAnchor(t *testing.T) {
	v := loadLedgerVectors(t)
	proof := InclusionProof{
		Leaf:            v.Inclusion.Leaf,
		BlockRoot:       v.Inclusion.BlockRoot,
		BlockProof:      v.Inclusion.BlockProof,
		CheckpointProof: v.Inclusion.CheckpointProof,
		CheckpointRoot:  v.Inclusion.DailyRoot,
	}
	if !VerifyInclusionProof(proof, v.Inclusion.DailyRoot) {
		t.Error("inclusion proof did not verify against its daily root")
	}
	if VerifyInclusionProof(proof, "0000000000000000000000000000000000000000000000000000000000000000") {
		t.Error("inclusion proof verified against a wrong root")
	}
	if got := AnchorDigestHex(v.Anchor.Input); got != v.Anchor.DigestHex {
		t.Errorf("AnchorDigestHex = %s, want %s", got, v.Anchor.DigestHex)
	}
}
