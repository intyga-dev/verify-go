package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func signedTestAnchor(t *testing.T, root, issuer string) (SignedAnchor, string) {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	a := SignedAnchor{AnchorInput: AnchorInput{root, "2026-09-16T00:00:00Z", issuer, "ES256"}, KeyID: "k"}
	d := anchorDigest(a.AnchorInput)
	h := sha256.Sum256(d[:])
	sig, e := ecdsa.SignASN1(rand.Reader, k, h[:])
	if e != nil {
		t.Fatal(e)
	}
	a.Signature = base64.StdEncoding.EncodeToString(sig)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return a, base64.StdEncoding.EncodeToString(der)
}

func TestAnchorQuorumAndDivergence(t *testing.T) {
	root := strings64("a")
	a, key := signedTestAnchor(t, root, "issuer-a")
	q := VerifyAnchorQuorum([]SignedAnchor{a}, root, AnchorPolicy{1, []string{"issuer-a"}, "N_OF_M"}, func(SignedAnchor) string { return key }, nil, ExternalAnchorKeys{})
	if !q.OK || len(q.VerifiedIssuers) != 1 {
		t.Fatalf("quorum failed: %+v", q)
	}
	other := a
	other.DailyRoot = strings64("b")
	d := anchorDigest(other.AnchorInput)
	_ = d // old signature must not create divergence
	q = VerifyAnchorQuorum(nil, root, AnchorPolicy{1, []string{"issuer-a"}, "N_OF_M"}, func(SignedAnchor) string { return key }, []SignedAnchor{other}, ExternalAnchorKeys{})
	if q.Divergence {
		t.Fatal("invalid signature declared divergence")
	}
}

func TestRootsChainContinuity(t *testing.T) {
	p := ""
	a := RootsChainEntry{SeqStart: "1", SeqEnd: "2", EntryCount: 2, Root: strings64("a"), AnchoredAt: "2026-09-15T00:00:00Z", PrevChainHash: &p}
	h := ChainHash(ChainInput{p, a.Root, a.SeqStart, a.SeqEnd, a.EntryCount, a.AnchoredAt})
	a.ChainHash = &h
	b := RootsChainEntry{SeqStart: "4", SeqEnd: "4", EntryCount: 1, Root: strings64("b"), AnchoredAt: "2026-09-16T00:00:00Z", PrevChainHash: &h}
	h2 := ChainHash(ChainInput{h, b.Root, b.SeqStart, b.SeqEnd, b.EntryCount, b.AnchoredAt})
	b.ChainHash = &h2
	if v := VerifyRootsChain([]RootsChainEntry{a, b}); !v.OK || v.VerifiedCount != 2 {
		t.Fatalf("chain failed: %+v", v)
	}
	bad := "bad"
	b.PrevChainHash = &bad
	if v := VerifyRootsChain([]RootsChainEntry{a, b}); v.OK || v.BrokenAt != 1 {
		t.Fatalf("broken chain accepted: %+v", v)
	}
}

func TestSelfCertifyingDIDFallback(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	b64 := base64.StdEncoding.EncodeToString(der)
	did := SelfCertifyingDID(b64)
	w := ApprovalWitness{SignerDID: did, SignerPublicKey: b64}
	keys, r := candidateKeys(ApproverTrustAnchor{DIDs: []string{did}}, w, nil)
	if r != "" || len(keys) != 1 || keys[0][1] != did {
		t.Fatalf("fallback failed: %s %+v", r, keys)
	}
	w.SignerPublicKey = base64.StdEncoding.EncodeToString([]byte("other"))
	if _, r := candidateKeys(ApproverTrustAnchor{DIDs: []string{did}}, w, nil); r == "" {
		t.Fatal("mismatched committed key accepted")
	}
}

func TestVerifyBundleRequiresIndependentRoot(t *testing.T) {
	leaf := HashLeaf("x")
	block := leaf
	root := HashLeaf(block)
	proof := InclusionProof{Leaf: leaf, BlockRoot: block, LeafIndex: 0, BlockLeafCount: 1, CheckpointRoot: root, CheckpointLeafIndex: 0, CheckpointLeafCount: 1}
	b := ProofBundle{Kind: BundleKind, Proof: proof, Event: BundleEvent{Seq: "1"}}
	if v := VerifyBundle(b, BundleVerifyOptions{}); v.OK || v.RootSource != "self-asserted" {
		t.Fatalf("self asserted bundle trusted: %+v", v)
	}
	if v := VerifyBundle(b, BundleVerifyOptions{TrustedRoot: root}); !v.OK || !v.Properties.CommitmentVerified {
		t.Fatalf("independent proof rejected: %+v", v)
	}
}

func strings64(s string) string {
	out := ""
	for len(out) < 64 {
		out += s
	}
	return out[:64]
}
