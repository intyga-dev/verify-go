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
		Leaf                string            `json:"leaf"`
		BlockIndex          string            `json:"blockIndex"`
		BlockRoot           string            `json:"blockRoot"`
		BlockProof          []LedgerProofStep `json:"blockProof"`
		LeafIndex           int               `json:"leafIndex"`
		BlockLeafCount      int               `json:"blockLeafCount"`
		CheckpointProof     []LedgerProofStep `json:"checkpointProof"`
		CheckpointLeafIndex int               `json:"checkpointLeafIndex"`
		CheckpointLeafCount int               `json:"checkpointLeafCount"`
		DailyRoot           string            `json:"dailyRoot"`
	} `json:"inclusion"`
	// InclusionNegative pins the duplicate-last padding forgery: proofs every conformant verifier
	// MUST refuse (DEWP §11.1). Without them the vectors only ever asserted that good input passes.
	InclusionNegative []struct {
		Name     string            `json:"name"`
		Reason   string            `json:"reason"`
		Leaf     string            `json:"leaf"`
		Proof    []LedgerProofStep `json:"proof"`
		Root     string            `json:"root"`
		Bounds   ProofBounds       `json:"bounds"`
		Expected bool              `json:"expected"`
	} `json:"inclusionNegative"`
	Anchor struct {
		Input     AnchorInput `json:"input"`
		DigestHex string      `json:"digestHex"`
	} `json:"anchor"`
	// SignedAnchor pins anchor SIGNING, not just the digest: the §5.2 trap is signing the digest's
	// 64-char hex text instead of its raw 32 bytes, and an implementation that falls into it still
	// matches every digest vector.
	SignedAnchor struct {
		SignerKey struct {
			SpkiB64 string `json:"spkiB64"`
		} `json:"signerKey"`
		Cases []struct {
			Name      string       `json:"name"`
			Anchor    SignedAnchor `json:"anchor"`
			DigestHex string       `json:"digestHex"`
			ExpectOk  bool         `json:"expectOk"`
		} `json:"cases"`
	} `json:"signedAnchor"`
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
		got, err := CanonicalPreimage(c.Row)
		if err != nil {
			t.Errorf("CanonicalPreimage[%s] refused a portable vector row: %v", c.Name, err)
			continue
		}
		if got != c.Canonical {
			t.Errorf("CanonicalPreimage[%s] =\n  %s\nwant\n  %s", c.Name, got, c.Canonical)
		}
		hash, err := LeafHash(c.Row)
		if err != nil {
			t.Errorf("LeafHash[%s] refused a portable vector row: %v", c.Name, err)
			continue
		}
		if hash != c.LeafHash {
			t.Errorf("LeafHash[%s] = %s, want %s", c.Name, hash, c.LeafHash)
		}
	}
}

func TestLedgerInclusionAndAnchor(t *testing.T) {
	v := loadLedgerVectors(t)
	proof := InclusionProof{
		Leaf:                v.Inclusion.Leaf,
		BlockRoot:           v.Inclusion.BlockRoot,
		BlockProof:          v.Inclusion.BlockProof,
		LeafIndex:           v.Inclusion.LeafIndex,
		BlockLeafCount:      v.Inclusion.BlockLeafCount,
		CheckpointProof:     v.Inclusion.CheckpointProof,
		CheckpointLeafIndex: v.Inclusion.CheckpointLeafIndex,
		CheckpointLeafCount: v.Inclusion.CheckpointLeafCount,
		CheckpointRoot:      v.Inclusion.DailyRoot,
	}
	if !VerifyInclusionProof(proof, v.Inclusion.DailyRoot) {
		t.Error("inclusion proof did not verify against its daily root")
	}
	if VerifyInclusionProof(proof, "0000000000000000000000000000000000000000000000000000000000000000") {
		t.Error("inclusion proof verified against a wrong root")
	}
	// A proof stripped of its position no longer establishes inclusion (DEWP §3 invariant 3).
	positionless := proof
	positionless.BlockLeafCount = 0
	if VerifyInclusionProof(positionless, v.Inclusion.DailyRoot) {
		t.Error("a proof that cannot say where its leaf sits must not verify")
	}
	if got := AnchorDigestHex(v.Anchor.Input); got != v.Anchor.DigestHex {
		t.Errorf("AnchorDigestHex = %s, want %s", got, v.Anchor.DigestHex)
	}
}

// TestLedgerSignedAnchorVectors drives the shared signedAnchor cases: an ES256 signature over the
// RAW 32-byte anchor digest verifies, and the same signature over a different root does not. A port
// that signs (or verifies against) the hex text of the digest fails the positive case here while
// passing every digest vector — the exact interop trap this section exists to catch.
func TestLedgerSignedAnchorVectors(t *testing.T) {
	v := loadLedgerVectors(t)
	if len(v.SignedAnchor.Cases) == 0 {
		t.Fatal("ledger-vectors.json carries no signedAnchor cases")
	}
	for _, c := range v.SignedAnchor.Cases {
		if c.DigestHex != "" {
			if got := AnchorDigestHex(c.Anchor.AnchorInput); got != c.DigestHex {
				t.Errorf("%s: AnchorDigestHex = %s, want %s", c.Name, got, c.DigestHex)
			}
		}
		if got := VerifyAnchorSignature(c.Anchor, v.SignedAnchor.SignerKey.SpkiB64); got != c.ExpectOk {
			t.Errorf("%s: VerifyAnchorSignature = %v, want %v", c.Name, got, c.ExpectOk)
		}
	}
}

// TestLedgerInclusionNegativeVectors runs the shared negative cases. This port previously had no
// leaf index or leaf count at all, so a path to a leaf slot that never existed recomputed the real
// root and verified — DEWP §11.1 calls that non-conformant outright.
func TestLedgerInclusionNegativeVectors(t *testing.T) {
	v := loadLedgerVectors(t)
	if len(v.InclusionNegative) == 0 {
		t.Fatal("ledger-vectors.json carries no inclusionNegative cases")
	}
	for _, c := range v.InclusionNegative {
		got := VerifyMerkleProof(c.Leaf, c.Proof, c.Root, c.Bounds)
		if got != c.Expected {
			t.Errorf("%s: VerifyMerkleProof = %v, want %v (%s)", c.Name, got, c.Expected, c.Reason)
		}
	}
}
