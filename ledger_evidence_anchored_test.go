package verify

// Bundle-level tests for DEWP §4.7.5 anchored time: where a record's anchored time may come from, how
// the §4.6.1 signature report and the §4.7.3 statement check agree on it, and the §4.7.4 findings a
// require-all policy fails on. The shared verifier-parity vectors pin the same surface across all
// five ports; these build their own one-block bundles with Rekor-witnessed checkpoints so the
// two-root case the vectors do not carry can be exercised.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	fixtureRekorIssuer = "https://rekor.sigstore.dev"
	fixtureAnchoredAt  = "2026-10-05T23:59:00.000Z"
)

type rekorLog struct {
	key  *ecdsa.PrivateKey
	spki string
}

func newRekorLog(t *testing.T) rekorLog {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return rekorLog{k, base64.StdEncoding.EncodeToString(der)}
}

// witness is a Rekor hashedrekord entry over cp's anchor digest, witnessed at integratedTime (Unix
// seconds) and SET-signed by the log key, as the shared execution-evidence vectors build theirs.
func (l rekorLog) witness(t *testing.T, cp AnchorInput, integratedTime int64) SignedAnchor {
	t.Helper()
	bodyJSON, _ := json.Marshal(map[string]interface{}{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]interface{}{
			"data":      map[string]interface{}{"hash": map[string]interface{}{"algorithm": "sha256", "value": RekorPayloadHashFor(cp)}},
			"signature": map[string]interface{}{"content": "c2ln", "publicKey": map[string]interface{}{"content": "cGs="}},
		},
	})
	body := base64.StdEncoding.EncodeToString(bodyJSON)
	logID := strings.Repeat("c0d23d6a", 8)
	// Rekor's SET covers this compact JSON in insertion order (see VerifyRekorAnchorPinned).
	bare, _ := json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{body, integratedTime, logID, 11})
	digest := sha256.Sum256(bare)
	set, err := ecdsa.SignASN1(rand.Reader, l.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	evidenceJSON, _ := json.Marshal(map[string]interface{}{
		"uuid": "e", "body": body, "integratedTime": integratedTime, "logID": logID, "logIndex": 11,
		"verification": map[string]interface{}{"signedEntryTimestamp": base64.StdEncoding.EncodeToString(set)},
	})
	evidence := base64.StdEncoding.EncodeToString(evidenceJSON)
	return SignedAnchor{AnchorInput: cp, KeyID: "rekor", Kind: "REKOR", Evidence: &evidence}
}

func unixSeconds(s string) int64 { return atTime(s).Unix() }

// checkpointOver is one checkpoint stating root over seqStart..seqEnd with its §5.4 chain hash.
func checkpointOver(id, root, seqStart, seqEnd string, entryCount int) EvidenceCheckpoint {
	prev := ""
	chain := ChainHash(ChainInput{PrevChainHash: prev, Root: root, SeqStart: seqStart, SeqEnd: seqEnd, EntryCount: entryCount, AnchoredAt: fixtureAnchoredAt})
	return EvidenceCheckpoint{ID: id, Root: root, AnchorRef: sp("self://" + id), AnchoredAt: sp(fixtureAnchoredAt), SeqStart: seqStart, SeqEnd: seqEnd,
		EntryCount: intp(entryCount), PrevChainHash: &prev, ChainHash: &chain}
}

func anchorInputOf(c EvidenceCheckpoint) AnchorInput {
	return AnchorInput{DailyRoot: c.Root, Timestamp: *c.AnchoredAt, Issuer: fixtureRekorIssuer, Algorithm: "ES256", SeqStart: c.SeqStart, SeqEnd: c.SeqEnd, ChainHash: *c.ChainHash}
}

// merklePath is the duplicate-last audit path for leaves[index], as MerkleRoot pairs them.
func merklePath(leaves []string, index int) []LedgerProofStep {
	steps := []LedgerProofStep{}
	level, idx := leaves, index
	for len(level) > 1 {
		sibling := idx ^ 1
		if sibling >= len(level) {
			sibling = idx
		}
		position := "RIGHT"
		if idx%2 == 1 {
			position = "LEFT"
		}
		steps = append(steps, LedgerProofStep{SiblingHash: level[sibling], SiblingPosition: position})
		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			right := level[i]
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, HashPair(level[i], right))
		}
		level, idx = next, idx/2
	}
	return steps
}

// oneBlockEntries commits rows as one block under one checkpoint and returns the entries with their
// inclusion proofs and the checkpoint root.
func oneBlockEntries(t *testing.T, rows []ExecutionEntry) ([]EvidenceEntry, string) {
	t.Helper()
	hashes := make([]string, len(rows))
	for i, r := range rows {
		h, err := LeafHash(r.Leaf)
		if err != nil {
			t.Fatal(err)
		}
		hashes[i] = h
	}
	blockRoot := MerkleRoot(hashes)
	root := MerkleRoot([]string{HashLeaf(blockRoot)})
	entries := make([]EvidenceEntry, len(rows))
	for i := range rows {
		leaf := rows[i].Leaf
		entries[i] = EvidenceEntry{
			Event: EvidenceEvent{Seq: *leaf.Seq, CreatedAt: *leaf.CreatedAt, Type: *leaf.Event, Outcome: *leaf.Outcome, SignerDID: leaf.SignerDid, SigAlg: leaf.SigAlg, Canonical: &leaf},
			Proof: InclusionProof{Leaf: hashes[i], BlockRoot: blockRoot, BlockProof: merklePath(hashes, i), LeafIndex: i, BlockLeafCount: len(rows),
				CheckpointProof: []LedgerProofStep{}, CheckpointLeafIndex: 0, CheckpointLeafCount: 1, CheckpointRoot: root},
		}
	}
	return entries, root
}

func evidenceBundleOf(entries []EvidenceEntry, checkpoints ...EvidenceCheckpoint) EvidenceBundle {
	b := EvidenceBundle{Kind: EvidenceBundleKind, Version: "1.0", Profile: AuditProfile, ExportedAt: fixtureAnchoredAt, Entries: entries, Checkpoints: checkpoints}
	b.Range.From, b.Range.To = t0, fixtureAnchoredAt
	return b
}

func rekorPolicy() *AnchorPolicy {
	return &AnchorPolicy{RequiredAnchors: 1, TrustedIssuers: []string{fixtureRekorIssuer}, Quorum: "N_OF_M"}
}

func signatureFor(r EvidenceVerification, seq string) AuditSignatureCheck {
	for _, c := range r.Signatures.Checks {
		if c.Seq == seq {
			return c.AuditSignatureCheck
		}
	}
	return AuditSignatureCheck{}
}

func TestAnchoredTimeComesOnlyFromTheRecordsOwnCheckpoint(t *testing.T) {
	log := newRekorLog(t)
	src := newEvidenceSource(t, "did:example:relay-7")
	rows := []ExecutionEntry{
		approvalEntry("100"),
		dispatchEntry("101", t0, ExecutionPayloadSha256(testApprovalPayload), plus(t0, time.Hour)),
		src.entry(t, "102", statementSpec{verdict: "confirmed", observedAt: plus(t0, time.Minute), sequence: 1}),
	}
	entries, rootA := oneBlockEntries(t, rows)
	// The record's own checkpoint, witnessed two minutes after its claimed time …
	witnessedA := "2026-10-06T00:01:00Z"
	cpA := checkpointOver("cp-a", rootA, "100", "102", 3)
	cpA.Anchors = []SignedAnchor{log.witness(t, anchorInputOf(cpA), unixSeconds(witnessedA))}
	// … and another checkpoint over an unrelated root whose stated range also covers seq 102,
	// witnessed EARLIER. Taking the earliest time across every covering checkpoint would backdate
	// the record to this witness.
	rootB := HashLeaf(HashLeaf("decoy"))
	cpB := checkpointOver("cp-b", rootB, "100", "999999999", 1)
	cpB.Anchors = []SignedAnchor{log.witness(t, anchorInputOf(cpB), unixSeconds("2026-10-05T23:59:30Z"))}
	// A key revoked between the two witness times: valid at B's, not at A's.
	revokedBetween := TrustedSourceKey{Key: src.spki, NotAfter: sp("2026-10-06T00:00:00.000Z")}
	opts := func(key TrustedSourceKey, roots ...string) EvidenceVerifyOptions {
		return EvidenceVerifyOptions{TrustedRoots: roots, AnchorPolicy: rekorPolicy(), ExternalKeys: ExternalAnchorKeys{Rekor: log.spki},
			ExecutionNow: atTime(plus(t0, 2*time.Minute)), EvidencePolicy: src.policy(key)}
	}

	r := VerifyEvidenceBundle(evidenceBundleOf(entries, cpA, cpB), opts(revokedBetween, rootA, rootB))
	if !r.OK || len(r.Roots) != 2 || !*r.Roots[0].AnchorVerified || !*r.Roots[1].AnchorVerified {
		t.Fatalf("both roots must anchor: ok=%v %+v %v", r.OK, r.Roots, r.Failed)
	}
	if c := r.Execution.Checks[0]; c.Status != "verified" || c.Trusted || !strings.Contains(c.Reason, "not valid at this record's anchored time") {
		t.Fatalf("the record's anchored time is its own checkpoint's witness, never another checkpoint's: %+v", c)
	}
	if s := signatureFor(r, "102"); s.Status != "verified" || s.Trusted || !strings.Contains(s.Reason, "not valid at this record's anchored time") {
		t.Fatalf("the §4.6.1 report uses the same anchored time: %+v", s)
	}
	if r.Execution.ByNonce[testNonce].Status != "pending" {
		t.Fatalf("%+v", r.Execution.ByNonce[testNonce])
	}
	// A key still valid at A's witness establishes trust, so the fixture does place the record in time.
	validThroughA := TrustedSourceKey{Key: src.spki, NotAfter: sp("2026-10-06T00:02:00.000Z")}
	r = VerifyEvidenceBundle(evidenceBundleOf(entries, cpA, cpB), opts(validThroughA, rootA, rootB))
	if c := r.Execution.Checks[0]; !r.OK || c.Status != "verified" || !c.Trusted || r.Execution.ByNonce[testNonce].Status != "confirmed" {
		t.Fatalf("%v %+v", r.OK, c)
	}
	if s := signatureFor(r, "102"); s.Status != "verified" || !s.Trusted {
		t.Fatalf("%+v", s)
	}
	// With the record's own checkpoint unwitnessed, the other checkpoint's witness lends it nothing.
	unwitnessed := cpA
	unwitnessed.Anchors = nil
	r = VerifyEvidenceBundle(evidenceBundleOf(entries, unwitnessed, cpB), opts(validThroughA, rootA, rootB))
	if c := r.Execution.Checks[0]; r.OK || c.Status != "verified" || c.Trusted || !strings.Contains(c.Reason, "cannot be placed in time") {
		t.Fatalf("%v %+v", r.OK, c)
	}
	if s := signatureFor(r, "102"); s.Status != "verified" || s.Trusted || !strings.Contains(s.Reason, "cannot be placed in time") {
		t.Fatalf("%+v", s)
	}
	// Only a seq inside the range the anchors were held to is placed: a checkpoint stating 100..101
	// over the same root still verifies the proof for seq 102, but its witness does not cover it.
	narrow := checkpointOver("cp-a", rootA, "100", "101", 3)
	narrow.Anchors = []SignedAnchor{log.witness(t, anchorInputOf(narrow), unixSeconds(witnessedA))}
	r = VerifyEvidenceBundle(evidenceBundleOf(entries, narrow), opts(validThroughA, rootA))
	if c := r.Execution.Checks[0]; !*r.Roots[0].AnchorVerified || c.Status != "verified" || c.Trusted || !strings.Contains(c.Reason, "cannot be placed in time") {
		t.Fatalf("%+v %+v", r.Roots, c)
	}
	// The caller's own checkpoint record decides that range where it states one.
	r = VerifyEvidenceBundle(evidenceBundleOf(entries, cpA), EvidenceVerifyOptions{
		TrustedCheckpoints: []TrustedCheckpoint{{Root: rootA, SeqStart: sp("100"), SeqEnd: sp("102"), EntryCount: intp(3), AnchoredAt: sp(fixtureAnchoredAt), ChainHash: cpA.ChainHash}},
		AnchorPolicy:       rekorPolicy(), ExternalKeys: ExternalAnchorKeys{Rekor: log.spki}, ExecutionNow: atTime(plus(t0, 2*time.Minute)), EvidencePolicy: src.policy(validThroughA),
	})
	if c := r.Execution.Checks[0]; !r.OK || !c.Trusted {
		t.Fatalf("%v %+v %v", r.OK, c, r.Failed)
	}
	// An unbounded key never needs an anchored time.
	r = VerifyEvidenceBundle(evidenceBundleOf(entries, unwitnessed, cpB), opts(TrustedSourceKey{Key: src.spki}, rootA, rootB))
	if c := r.Execution.Checks[0]; c.Status != "verified" || !c.Trusted {
		t.Fatalf("%+v", c)
	}
}

func TestSingleProofSignatureAndStatementAgreeOnABoundedKey(t *testing.T) {
	log := newRekorLog(t)
	src := newEvidenceSource(t, "did:example:relay-7")
	rows := []ExecutionEntry{
		approvalEntry("100"),
		dispatchEntry("101", t0, ExecutionPayloadSha256(testApprovalPayload), plus(t0, time.Hour)),
		src.entry(t, "102", statementSpec{verdict: "contradicted", observedAt: plus(t0, time.Minute), sequence: 1}),
	}
	entries, root := oneBlockEntries(t, rows)
	cp := checkpointOver("cp", root, "100", "102", 3)
	anchor := log.witness(t, anchorInputOf(cp), unixSeconds("2026-10-06T00:01:00Z"))
	leaf := rows[2].Leaf
	bundle := ProofBundle{Kind: BundleKind, Version: "1.0", Profile: AuditProfile,
		Event: BundleEvent{Seq: "102", CreatedAt: *leaf.CreatedAt, Type: *leaf.Event, Outcome: *leaf.Outcome, SignerDID: leaf.SignerDid, SigAlg: leaf.SigAlg, Canonical: &leaf},
		Proof: entries[2].Proof, Anchors: []SignedAnchor{anchor}}
	record := &TrustedCheckpoint{Root: root, SeqStart: sp("100"), SeqEnd: sp("102"), EntryCount: intp(3), AnchoredAt: sp(fixtureAnchoredAt), ChainHash: cp.ChainHash}
	verify := func(key TrustedSourceKey, record *TrustedCheckpoint, trustedRoot string) BundleVerification {
		return VerifyBundle(bundle, BundleVerifyOptions{TrustedRoot: trustedRoot, TrustedCheckpoint: record, AnchorPolicy: rekorPolicy(),
			ExternalKeys: ExternalAnchorKeys{Rekor: log.spki}, EvidencePolicy: src.policy(key)})
	}
	revoked := TrustedSourceKey{Key: src.spki, NotAfter: sp("2026-10-06T00:00:00.000Z")}
	valid := TrustedSourceKey{Key: src.spki, NotAfter: sp("2026-10-06T00:02:00.000Z")}

	r := verify(valid, record, "")
	if !r.OK || !r.Properties.AnchorVerified || r.Execution == nil {
		t.Fatalf("%+v", r)
	}
	if r.Execution.Status != "unbound" || !r.Execution.Trusted || r.Signature.Status != "verified" || !r.Signature.Trusted {
		t.Fatalf("placed inside the interval, both reports trust the key: %+v %+v", r.Execution, r.Signature)
	}
	r = verify(revoked, record, "")
	if r.Execution.Status != "unbound" || r.Execution.Trusted || r.Signature.Status != "verified" || r.Signature.Trusted ||
		!strings.Contains(r.Execution.Reason, "not valid at this record's anchored time") || !strings.Contains(r.Signature.Reason, "not valid at this record's anchored time") {
		t.Fatalf("placed outside it, both reports refuse: %+v %+v", r.Execution, r.Signature)
	}
	// Without the caller's checkpoint record no external witness counts, so the key is never placed.
	r = verify(valid, nil, root)
	if r.Properties.AnchorVerified || r.Execution.Trusted || r.Signature.Trusted || !strings.Contains(r.Signature.Reason, "cannot be placed in time") {
		t.Fatalf("%+v %+v", r.Execution, r.Signature)
	}
}

// executionVectorCase loads one `executionEvidence` bundle case from the shared parity vectors.
func executionVectorCase(t *testing.T, name string) (EvidenceBundle, EvidenceVerifyOptions) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("vectors", "verifier-parity-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ExecutionEvidence struct {
			Cases []struct {
				Name    string          `json:"name"`
				Bundle  json.RawMessage `json:"bundle"`
				Policy  *AnchorPolicy   `json:"policy"`
				Options struct {
					TrustedRoots              []string                 `json:"trustedRoots"`
					EvidencePolicy            *ExecutionEvidencePolicy `json:"evidencePolicy"`
					SignaturePolicy           *AuditSignaturePolicy    `json:"signaturePolicy"`
					Now                       string                   `json:"now"`
					SkewSeconds               *int                     `json:"skewSeconds"`
					MaxWindowSeconds          *int                     `json:"maxWindowSeconds"`
					RequireExecutionConfirmed bool                     `json:"requireExecutionConfirmed"`
					RekorSpki                 string                   `json:"rekorSpki"`
				} `json:"options"`
			} `json:"cases"`
		} `json:"executionEvidence"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.ExecutionEvidence.Cases {
		if c.Name != name {
			continue
		}
		var bundle EvidenceBundle
		if err := json.Unmarshal(c.Bundle, &bundle); err != nil {
			t.Fatal(err)
		}
		now, err := time.Parse(time.RFC3339Nano, c.Options.Now)
		if err != nil {
			t.Fatal(err)
		}
		return bundle, EvidenceVerifyOptions{
			TrustedRoots: c.Options.TrustedRoots, EvidencePolicy: c.Options.EvidencePolicy, SignaturePolicy: c.Options.SignaturePolicy,
			ExecutionNow: &now, EvidenceSkewSeconds: c.Options.SkewSeconds, MaxEvidenceWindowSeconds: c.Options.MaxWindowSeconds,
			RequireExecutionConfirmed: c.Options.RequireExecutionConfirmed, AnchorPolicy: c.Policy, ExternalKeys: ExternalAnchorKeys{Rekor: c.Options.RekorSpki},
		}
	}
	t.Fatalf("no execution-evidence vector case named %q", name)
	return EvidenceBundle{}, EvidenceVerifyOptions{}
}

func failureReasons(r EvidenceVerification) []string {
	out := []string{}
	for _, f := range r.Failed {
		out = append(out, f.Reason)
	}
	return out
}

func TestRootListedTwiceWithDifferentFieldsIsRefused(t *testing.T) {
	bundle, opts := executionVectorCase(t, "confirmed")
	if r := VerifyEvidenceBundle(bundle, opts); !r.OK {
		t.Fatalf("%v", r.Failed)
	}
	first := bundle.Checkpoints[0]
	// An identical second listing is tolerated, anchors and anchorRef aside.
	identical := first
	identical.AnchorRef = sp("other://ref")
	identical.Anchors = nil
	bundle.Checkpoints = []EvidenceCheckpoint{first, identical}
	if r := VerifyEvidenceBundle(bundle, opts); !r.OK || len(r.Roots) != 1 {
		t.Fatalf("identical duplicates are tolerated: %v %d", r.Failed, len(r.Roots))
	}
	// Each field the comparison covers, differing on its own, refuses the bundle.
	variants := map[string]func(c *EvidenceCheckpoint){
		"id":            func(c *EvidenceCheckpoint) { c.ID = "cp-x-copy" },
		"seqEnd":        func(c *EvidenceCheckpoint) { c.SeqEnd = "999999999" },
		"seqStart":      func(c *EvidenceCheckpoint) { c.SeqStart = "1" },
		"entryCount":    func(c *EvidenceCheckpoint) { c.EntryCount = nil },
		"anchoredAt":    func(c *EvidenceCheckpoint) { c.AnchoredAt = sp("2026-10-04T23:59:00.000Z") },
		"chainHash":     func(c *EvidenceCheckpoint) { c.ChainHash = nil },
		"prevChainHash": func(c *EvidenceCheckpoint) { c.PrevChainHash = nil },
	}
	for name, mutate := range variants {
		copy := first
		mutate(&copy)
		bundle.Checkpoints = []EvidenceCheckpoint{first, copy}
		r := VerifyEvidenceBundle(bundle, opts)
		want := "checkpoint " + copy.ID + " lists a root the bundle already states with different fields"
		found := false
		for _, reason := range failureReasons(r) {
			found = found || reason == want
		}
		if r.OK || !found {
			t.Errorf("%s: ok=%v %v", name, r.OK, failureReasons(r))
		}
		// The first listing still decides the position; the second never shadows it.
		if len(r.Roots) != 1 || r.ContentVerified != 4 {
			t.Errorf("%s: %d roots, %d content-verified", name, len(r.Roots), r.ContentVerified)
		}
	}
}

func TestRequiredConfirmationFailsOnUncountedContradictions(t *testing.T) {
	for name, want := range map[string]string{
		"late-contradiction-fails-required":      "has a late contradiction (seq 103)",
		"untrusted-contradiction-fails-required": "has a contradiction under a provisioned key that established no trust (seq 103)",
	} {
		bundle, opts := executionVectorCase(t, name)
		r := VerifyEvidenceBundle(bundle, opts)
		if r.OK || r.Execution.ByNonce["4f6c1c9e-1b8a-4e2f-9d3a-7c2b5e8f0a1d"].Status != "confirmed" {
			t.Fatalf("%s: ok=%v %+v", name, r.OK, r.Execution.ByNonce)
		}
		reasons := failureReasons(r)
		if len(reasons) != 1 || !strings.HasPrefix(reasons[0], "Required confirmed execution: nonce ") || !strings.HasSuffix(reasons[0], want) || r.Failed[0].Seq != "103" {
			t.Errorf("%s: %v", name, r.Failed)
		}
		// Without the policy the finding is reported and nothing fails.
		opts.RequireExecutionConfirmed = false
		if r := VerifyEvidenceBundle(bundle, opts); !r.OK {
			t.Errorf("%s: %v", name, r.Failed)
		}
	}
	bundle, opts := executionVectorCase(t, "untrusted-contradiction-fails-required")
	r := VerifyEvidenceBundle(bundle, opts)
	if !reflect.DeepEqual(r.Execution.UntrustedContradicted, []string{"4f6c1c9e-1b8a-4e2f-9d3a-7c2b5e8f0a1d"}) ||
		!reflect.DeepEqual(r.Execution.ByNonce["4f6c1c9e-1b8a-4e2f-9d3a-7c2b5e8f0a1d"].UntrustedContradiction, []string{"103"}) {
		t.Errorf("%+v", r.Execution)
	}
}
