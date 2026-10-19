package verify

// Focused tests for the DEWP §4.7 rules tightened in the pre-publication review. The shared
// verifier-parity vectors pin the same surface across all five ports; these exercise the Go
// evaluator directly on synthetic content-verified entries, where each rule is easiest to read.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	testApprovalPayload = `{"nonce":"n-1","type":"div-intent-verification","v":1}`
	testNonce           = "n-1"
	t0                  = "2026-10-05T14:00:00.000Z"
)

type evidenceSource struct {
	key  *ecdsa.PrivateKey
	spki string
	did  string
}

func newEvidenceSource(t *testing.T, did string) evidenceSource {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return evidenceSource{k, base64.StdEncoding.EncodeToString(der), did}
}

func sp(s string) *string { return &s }

func atTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return &t
}

func plus(s string, d time.Duration) string {
	return atTime(s).Add(d).UTC().Format(dewpTimestampLayout)
}

func approvalEntry(seq string) ExecutionEntry {
	return ExecutionEntry{seq, AuditLeaf{Seq: sp(seq), CreatedAt: sp(t0), Event: sp("AUTHZ_APPROVED"), Outcome: sp("SUCCESS"), SignedPayload: sp(testApprovalPayload)}}
}

func dispatchEntry(seq, createdAt, hash, deadline string) ExecutionEntry {
	return ExecutionEntry{seq, AuditLeaf{Seq: sp(seq), CreatedAt: sp(createdAt), Event: sp(ExecutionDispatched), Outcome: sp("PENDING"),
		Metadata: map[string]interface{}{"nonce": testNonce, "payloadSha256": hash, "evidenceDeadline": deadline}}}
}

type statementSpec struct {
	verdict               string
	observedAt, sampledAt string
	sequence              int64
	hash                  string
	observation           map[string]interface{}
}

// entry signs a statement and wraps it as an Evidence Record whose event/outcome match the verdict.
func (s evidenceSource) entry(t *testing.T, seq string, spec statementSpec) ExecutionEntry {
	t.Helper()
	hash := spec.hash
	if hash == "" {
		hash = ExecutionPayloadSha256(testApprovalPayload)
	}
	sampledAt := spec.sampledAt
	if sampledAt == "" {
		sampledAt = spec.observedAt
	}
	bytes, err := CanonicalExecutionEvidenceStatement(ExecutionEvidenceStatement{
		Nonce: testNonce, PayloadSha256: hash, Observation: spec.observation, ObservedAt: spec.observedAt,
		SampledAt: sampledAt, Sequence: spec.sequence, Source: s.did, Verdict: spec.verdict,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(bytes))
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return ExecutionEntry{seq, AuditLeaf{Seq: sp(seq), CreatedAt: sp(spec.observedAt), Event: sp(verdictEvent[spec.verdict]),
		Outcome: sp(verdictOutcome[spec.verdict]), SignerDid: sp(s.did), SignerPublicKey: sp(s.spki), SignedPayload: sp(bytes),
		Signature: sp(base64.StdEncoding.EncodeToString(sig)), SigAlg: sp("ES256")}}
}

func (s evidenceSource) policy(keys ...TrustedSourceKey) *ExecutionEvidencePolicy {
	if len(keys) == 0 {
		keys = []TrustedSourceKey{{Key: s.spki}}
	}
	return &ExecutionEvidencePolicy{TrustedSources: map[string][]TrustedSourceKey{s.did: keys}}
}

func intp(v int) *int { return &v }

func TestStatementSequenceAndSampledAtRules(t *testing.T) {
	base := ExecutionEvidenceStatement{
		Nonce: testNonce, PayloadSha256: ExecutionPayloadSha256(testApprovalPayload), Observation: map[string]interface{}{"breaker": "open"},
		ObservedAt: "2026-10-05T14:02:11.000Z", SampledAt: "2026-10-05T14:02:09.500Z", Sequence: 418, Source: "did:example:relay-7", Verdict: "confirmed",
	}
	bytes, err := CanonicalExecutionEvidenceStatement(base)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseExecutionEvidenceStatement(bytes)
	if err != nil || parsed.Sequence != 418 || parsed.SampledAt != base.SampledAt {
		t.Fatalf("%+v %v", parsed, err)
	}
	// The builder refuses what a verifier would refuse, so a source never signs malformed bytes.
	for name, mutate := range map[string]func(s *ExecutionEvidenceStatement){
		"sequence zero":            func(s *ExecutionEvidenceStatement) { s.Sequence = 0 },
		"sequence negative":        func(s *ExecutionEvidenceStatement) { s.Sequence = -1 },
		"sequence above 2^53":      func(s *ExecutionEvidenceStatement) { s.Sequence = 9007199254740992 },
		"sampled after observed":   func(s *ExecutionEvidenceStatement) { s.SampledAt = "2026-10-05T14:02:11.001Z" },
		"sampled without millis":   func(s *ExecutionEvidenceStatement) { s.SampledAt = "2026-10-05T14:02:09Z" },
		"sampled missing":          func(s *ExecutionEvidenceStatement) { s.SampledAt = "" },
		"non-portable observation": func(s *ExecutionEvidenceStatement) { s.Observation = map[string]interface{}{"x": 1e16} },
	} {
		s := base
		mutate(&s)
		if _, err := CanonicalExecutionEvidenceStatement(s); err == nil {
			t.Errorf("builder accepted %s", name)
		}
	}
	// Byte-level spellings of `sequence` (DEWP §4.7.2 rules 9 and 12).
	for spelling, ok := range map[string]bool{
		"418": true, "9007199254740991": true,
		"418.0": false, "418.5": false, `"418"`: false, "0": false, "-1": false, "9007199254740992": false, "1e2": false,
	} {
		mutated := strings.Replace(bytes, `"sequence":418`, `"sequence":`+spelling, 1)
		if mutated == bytes && spelling != "418" {
			t.Fatal("test fixture did not substitute the sequence")
		}
		if _, err := ParseExecutionEvidenceStatement(mutated); (err == nil) != ok {
			t.Errorf("sequence %s: ok=%v want %v (%v)", spelling, err == nil, ok, err)
		}
	}
	// The seven-member draft shape is malformed now.
	draft := strings.Replace(bytes, `"sampledAt":"2026-10-05T14:02:09.500Z","sequence":418,`, "", 1)
	if _, err := ParseExecutionEvidenceStatement(draft); err == nil || !strings.Contains(err.Error(), "exactly the members") {
		t.Errorf("draft shape: %v", err)
	}
}

func TestTrustedSourceKeyJSONForms(t *testing.T) {
	var p ExecutionEvidencePolicy
	// K1 bare; K2 bounded; 42 and {"notBefore":"x"} carry no usable key and are dropped; K3 has a
	// numeric bound, K4 a misspelt one, K5 a null bound, K6 an extra member beside a good bound — each
	// is KEPT (its signature verifies) and marked malformed (it trusts nothing); "" is dropped.
	raw := `{"trustedSources":{"s":["K1",{"key":"K2","notAfter":"2026-10-07T00:00:00.000Z"},42,{"notBefore":"x"},` +
		`{"key":"K3","notBefore":7},{"key":"K4","notafter":"2026-10-05T18:00:00.000Z"},{"key":"K5","notAfter":null},` +
		`{"key":"K6","notAfter":"2026-10-07T00:00:00.000Z","comment":"rotated","alg":"ES256"},""]}}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	keys := trustedKeysFor(&p, sp("s"))
	if len(keys) != 6 {
		t.Fatalf("entries without a usable key are dropped, nothing else is: %+v", keys)
	}
	want := []struct {
		key       string
		malformed string
	}{
		{"K1", ""},
		{"K2", ""},
		{"K3", "Caller key entry's notBefore is not a timestamp string; it does not establish trust."},
		{"K4", "Caller key entry has unexpected member(s) notafter; it does not establish trust."},
		{"K5", "Caller key entry's notAfter is not a timestamp string; it does not establish trust."},
		{"K6", "Caller key entry has unexpected member(s) alg, comment; it does not establish trust."},
	}
	for i, w := range want {
		if keys[i].Key != w.key || keys[i].Malformed() != w.malformed {
			t.Errorf("entry %d: %q %q want %q %q", i, keys[i].Key, keys[i].Malformed(), w.key, w.malformed)
		}
	}
	if keys[1].NotAfter == nil || keys[2].NotBefore != nil || keys[4].NotAfter != nil || keys[5].NotAfter == nil {
		t.Errorf("a bound is stored only when it is a string: %+v", keys)
	}
	// A malformed entry trusts nothing even at an anchored time inside its (string) bound.
	inside := atTime("2026-10-06T00:00:00Z").UnixMilli()
	for _, i := range []int{2, 3, 4, 5} {
		if ok, reason := keyValidAt(keys[i], &inside); ok || reason != want[i].malformed {
			t.Errorf("entry %d: valid=%v %q", i, ok, reason)
		}
	}
	if ok, _ := keyValidAt(keys[1], &inside); !ok {
		t.Error("a well-formed bounded key is valid inside its interval")
	}
	if out, _ := json.Marshal(keys[0]); string(out) != `"K1"` {
		t.Errorf("bare key marshals as a string: %s", out)
	}
	if out, _ := json.Marshal(keys[1]); string(out) != `{"key":"K2","notAfter":"2026-10-07T00:00:00.000Z"}` {
		t.Errorf("bounded key marshals as an object: %s", out)
	}
	// Marshalling never launders a malformed entry into a well-formed one: it round-trips as received.
	if out, _ := json.Marshal(keys[3]); string(out) != `{"key":"K4","notafter":"2026-10-05T18:00:00.000Z"}` {
		t.Errorf("malformed entry round-trips its own bytes: %s", out)
	}
	var again ExecutionEvidencePolicy
	round, _ := json.Marshal(p)
	if err := json.Unmarshal(round, &again); err != nil {
		t.Fatal(err)
	}
	if got := trustedKeysFor(&again, sp("s")); len(got) != 6 || got[3].Malformed() != want[3].malformed {
		t.Errorf("round trip: %+v", got)
	}
	if trustedKeysFor(&p, sp("unknown")) != nil || trustedKeysFor(nil, sp("s")) != nil {
		t.Error("no keys for an unknown source or without a policy")
	}
	// A Go-constructed value cannot be malformed.
	if (TrustedSourceKey{Key: "K", NotAfter: sp("2026-10-07T00:00:00.000Z")}).Malformed() != "" {
		t.Error("constructed keys are well-formed by type")
	}
}

func TestMalformedKeyEntriesVerifyButNeverTrust(t *testing.T) {
	src := newEvidenceSource(t, "did:example:relay-7")
	entries := []ExecutionEntry{
		approvalEntry("100"),
		dispatchEntry("101", t0, ExecutionPayloadSha256(testApprovalPayload), plus(t0, time.Hour)),
		src.entry(t, "102", statementSpec{verdict: "contradicted", observedAt: plus(t0, time.Minute), sequence: 1}),
	}
	inside := atTime("2026-10-05T23:59:00Z").UnixMilli()
	anchored := func(string) (int64, bool) { return inside, true }
	for name, entry := range map[string]string{
		"numeric bound":       `{"key":%q,"notAfter":1754006400000}`,
		"misspelt bound":      `{"key":%q,"notafter":"2026-10-05T18:00:00.000Z"}`,
		"null bound":          `{"key":%q,"notBefore":null}`,
		"extra member":        `{"key":%q,"notBefore":"2026-10-01T00:00:00.000Z","label":"relay"}`,
		"non-timestamp bound": `{"key":%q,"notAfter":"soon"}`,
	} {
		var p ExecutionEvidencePolicy
		if err := json.Unmarshal([]byte(`{"trustedSources":{"`+src.did+`":[`+strings.Replace(entry, "%q", `"`+src.spki+`"`, 1)+`]}}`), &p); err != nil {
			t.Fatal(err)
		}
		r := EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: &p, Now: atTime(plus(t0, 2*time.Minute)), AnchoredTime: anchored})
		c := r.Checks[0]
		if c.Status != "verified" || c.Trusted || !strings.Contains(c.Reason, "does not establish trust") {
			t.Errorf("%s: the signature verifies, the key trusts nothing: %+v", name, c)
		}
		// … and a contradiction so refused is still the §4.7.4 finding, never silent.
		if r.ByNonce[testNonce].Status != "pending" || !reflect.DeepEqual(r.UntrustedContradicted, []string{testNonce}) {
			t.Errorf("%s: %+v %v", name, r.ByNonce[testNonce], r.UntrustedContradicted)
		}
		if s := VerifyAuditSignatureWithEvidence(entries[2].Leaf, nil, &p, &inside); s.Status != "verified" || s.Trusted {
			t.Errorf("%s: the §4.6.1 report agrees: %+v", name, s)
		}
	}
	// An entry with no usable key is not provisioned at all: nothing verifies under it.
	var p ExecutionEvidencePolicy
	if err := json.Unmarshal([]byte(`{"trustedSources":{"`+src.did+`":[{"notAfter":"2026-10-07T00:00:00.000Z"},{"key":""},7]}}`), &p); err != nil {
		t.Fatal(err)
	}
	r := EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: &p, Now: atTime(plus(t0, 2*time.Minute)), AnchoredTime: anchored})
	if c := r.Checks[0]; c.Status != "not_checked" || len(r.UntrustedContradicted) != 0 {
		t.Errorf("%+v %v", c, r.UntrustedContradicted)
	}
}

func TestUntrustedContradictionIsAFinding(t *testing.T) {
	src := newEvidenceSource(t, "did:example:relay-7")
	hash := ExecutionPayloadSha256(testApprovalPayload)
	contradiction := func(seq string, spec statementSpec) ExecutionEntry {
		spec.verdict = "contradicted"
		return src.entry(t, seq, spec)
	}
	inWindow := statementSpec{observedAt: plus(t0, time.Minute), sequence: 1}
	entries := []ExecutionEntry{approvalEntry("100"), dispatchEntry("101", t0, hash, plus(t0, time.Hour)), contradiction("102", inWindow)}
	bounded := TrustedSourceKey{Key: src.spki, NotAfter: sp("2026-10-07T00:00:00.000Z")}
	now := atTime(plus(t0, 2*time.Minute))
	at := func(ms int64) func(string) (int64, bool) { return func(string) (int64, bool) { return ms, true } }

	// Bound, in-window, signature verified under a provisioned key the bundle cannot place in time.
	r := EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(bounded), Now: now})
	n := r.ByNonce[testNonce]
	if c := r.Checks[0]; c.Status != "verified" || c.Trusted || n.Status != "pending" {
		t.Fatalf("it cannot decide the status: %+v %+v", c, n)
	}
	if !reflect.DeepEqual(n.UntrustedContradiction, []string{"102"}) || !reflect.DeepEqual(r.UntrustedContradicted, []string{testNonce}) || len(r.LateContradicted) != 0 {
		t.Fatalf("… and it is never silent: %+v %+v", n, r)
	}
	// The same key outside its interval at a known anchored time.
	r = EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(bounded), Now: now, AnchoredTime: at(atTime("2026-10-08T00:00:00Z").UnixMilli())})
	if !reflect.DeepEqual(r.UntrustedContradicted, []string{testNonce}) || r.ByNonce[testNonce].Status != "pending" {
		t.Fatalf("%+v", r.ByNonce[testNonce])
	}
	// Inside its interval the key establishes trust: the status is contradicted and there is no finding.
	r = EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(bounded), Now: now, AnchoredTime: at(atTime("2026-10-05T23:59:00Z").UnixMilli())})
	if r.ByNonce[testNonce].Status != "contradicted" || len(r.UntrustedContradicted) != 0 || len(r.ByNonce[testNonce].UntrustedContradiction) != 0 {
		t.Fatalf("%+v %v", r.ByNonce[testNonce], r.UntrustedContradicted)
	}
	// Lateness does not silence a contradiction signed by a provisioned key without established trust.
	late := []ExecutionEntry{entries[0], entries[1], contradiction("102", statementSpec{observedAt: plus(t0, 2*time.Hour), sequence: 1})}
	r = EvaluateExecutionEvidence(late, ExecutionEvaluationOptions{Policy: src.policy(bounded), Now: now})
	if r.Checks[0].Status != "stale" || r.Checks[0].Trusted || !reflect.DeepEqual(r.UntrustedContradicted, []string{testNonce}) || len(r.LateContradicted) != 0 || !reflect.DeepEqual(r.ByNonce[testNonce].UntrustedContradiction, []string{"102"}) {
		t.Fatalf("late untrusted contradiction must remain a finding: %+v", r)
	}
	// Cases that are NOT this finding.
	for name, variant := range map[string]struct {
		entries []ExecutionEntry
		policy  *ExecutionEvidencePolicy
	}{
		// No policy means no provisioned key: an embedded-key contradiction is not the finding.
		"embedded key": {entries, nil},
		// Untrusted and early.
		"early": {[]ExecutionEntry{entries[0], entries[1], contradiction("102", statementSpec{observedAt: plus(t0, -time.Hour), sequence: 1})}, src.policy(bounded)},
		// Untrusted and unbound (another hash).
		"unbound": {[]ExecutionEntry{entries[0], entries[1], contradiction("102", statementSpec{observedAt: plus(t0, time.Minute), sequence: 1, hash: strings.Repeat("c", 64)})}, src.policy(bounded)},
		// An untrusted CONFIRMED is not a contradiction.
		"confirmed": {[]ExecutionEntry{entries[0], entries[1], src.entry(t, "102", statementSpec{verdict: "confirmed", observedAt: plus(t0, time.Minute), sequence: 1})}, src.policy(bounded)},
		// A key for another source: the statement is not_checked, not verified.
		"not provisioned": {entries, &ExecutionEvidencePolicy{TrustedSources: map[string][]TrustedSourceKey{"did:example:other": {bounded}}}},
	} {
		r := EvaluateExecutionEvidence(variant.entries, ExecutionEvaluationOptions{Policy: variant.policy, Now: now})
		if len(r.UntrustedContradicted) != 0 || len(r.ByNonce[testNonce].UntrustedContradiction) != 0 || len(r.LateContradicted) != 0 {
			t.Errorf("%s: %+v %v %v", name, r.ByNonce[testNonce], r.UntrustedContradicted, r.LateContradicted)
		}
		if r.ByNonce[testNonce].Status == "contradicted" {
			t.Errorf("%s: an untrusted statement never decides a status", name)
		}
	}
}

func TestNegativeOptionsFallBackToDefaults(t *testing.T) {
	src := newEvidenceSource(t, "did:example:relay-7")
	hash := ExecutionPayloadSha256(testApprovalPayload)
	now := atTime(plus(t0, 2*time.Hour))
	// Sampled 20 s before dispatch: inside the default 30 s skew; a honoured −1 s would make it early.
	early := []ExecutionEntry{approvalEntry("100"), dispatchEntry("101", t0, hash, plus(t0, time.Hour)),
		src.entry(t, "102", statementSpec{verdict: "confirmed", observedAt: plus(t0, time.Minute), sampledAt: plus(t0, -20*time.Second), sequence: 1})}
	for _, skew := range []*int{intp(-1), intp(-86400)} {
		r := EvaluateExecutionEvidence(early, ExecutionEvaluationOptions{Policy: src.policy(), Now: now, SkewSeconds: skew})
		if c := r.Checks[0]; c.Status != "verified" || r.ByNonce[testNonce].Status != "confirmed" {
			t.Errorf("skew %d must fall back to the default: %+v", *skew, c)
		}
	}
	if r := EvaluateExecutionEvidence(early, ExecutionEvaluationOptions{Policy: src.policy(), Now: now, SkewSeconds: intp(10)}); r.Checks[0].Status != "stale" {
		t.Errorf("a non-negative skew is honoured: %+v", r.Checks[0])
	}
	// Sampled 30 min after dispatch, inside the record's 1 h deadline and the default 24 h window; a
	// honoured −1 s window would cut the deadline to before dispatch and make it late.
	late := []ExecutionEntry{approvalEntry("100"), dispatchEntry("101", t0, hash, plus(t0, time.Hour)),
		src.entry(t, "102", statementSpec{verdict: "confirmed", observedAt: plus(t0, 30*time.Minute), sequence: 1})}
	for _, window := range []*int{intp(-1), intp(-3600)} {
		r := EvaluateExecutionEvidence(late, ExecutionEvaluationOptions{Policy: src.policy(), Now: now, MaxWindowSeconds: window})
		n := r.ByNonce[testNonce]
		if c := r.Checks[0]; c.Status != "verified" || n.Status != "confirmed" || n.WindowCapped || *n.EffectiveDeadline != plus(t0, time.Hour) {
			t.Errorf("window %d must fall back to the default: %+v %+v", *window, c, n)
		}
	}
	if r := EvaluateExecutionEvidence(late, ExecutionEvaluationOptions{Policy: src.policy(), Now: now, MaxWindowSeconds: intp(60)}); r.Checks[0].Status != "stale" || !r.ByNonce[testNonce].WindowCapped {
		t.Errorf("a non-negative window is honoured: %+v", r.Checks[0])
	}
	// Zero is a bound, not an absence: no skew at all, and a window that closes at dispatch.
	if r := EvaluateExecutionEvidence(early, ExecutionEvaluationOptions{Policy: src.policy(), Now: now, SkewSeconds: intp(0)}); r.Checks[0].Status != "stale" {
		t.Errorf("zero skew: %+v", r.Checks[0])
	}
	if r := EvaluateExecutionEvidence(late, ExecutionEvaluationOptions{Policy: src.policy(), Now: now, MaxWindowSeconds: intp(0)}); r.Checks[0].Status != "stale" || !r.ByNonce[testNonce].WindowCapped {
		t.Errorf("zero window: %+v", r.Checks[0])
	}
}

func TestBindingSurvivesAnEarlyConflictingDispatch(t *testing.T) {
	src := newEvidenceSource(t, "did:example:relay-7")
	other := strings.Repeat("a", 64)
	entries := []ExecutionEntry{
		approvalEntry("100"),
		dispatchEntry("101", t0, other, plus(t0, time.Hour)),
		dispatchEntry("102", t0, ExecutionPayloadSha256(testApprovalPayload), plus(t0, time.Hour)),
		src.entry(t, "103", statementSpec{verdict: "contradicted", observedAt: plus(t0, 5*time.Minute), sequence: 1}),
	}
	r := EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(), Now: atTime(plus(t0, 10*time.Minute))})
	if c := r.Checks[0]; c.Status != "verified" || !c.Trusted || *c.Source != src.did || *c.Sequence != 1 {
		t.Fatalf("an early record with another hash must not unbind a genuine statement: %+v", c)
	}
	n := r.ByNonce[testNonce]
	if n.Status != "contradicted" || *n.DispatchSeq != "102" || !reflect.DeepEqual(n.DispatchConflict, []string{"101", "102"}) {
		t.Fatalf("%+v", n)
	}
	if !reflect.DeepEqual(r.DispatchConflicts, []string{testNonce}) || !reflect.DeepEqual(r.Contradicted, []string{testNonce}) {
		t.Fatalf("%+v", r)
	}
	// Agreeing records are no conflict; the lowest-seq matching one governs.
	entries[1] = dispatchEntry("101", t0, ExecutionPayloadSha256(testApprovalPayload), plus(t0, 2*time.Hour))
	r = EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(), Now: atTime(plus(t0, 10*time.Minute))})
	if n := r.ByNonce[testNonce]; *n.DispatchSeq != "101" || len(n.DispatchConflict) != 0 || len(r.DispatchConflicts) != 0 {
		t.Fatalf("%+v %v", n, r.DispatchConflicts)
	}
	// The two unbound reasons are told apart.
	r = EvaluateExecutionEvidence([]ExecutionEntry{entries[0], dispatchEntry("101", t0, other, plus(t0, time.Hour)), entries[3]}, ExecutionEvaluationOptions{Policy: src.policy()})
	if c := r.Checks[0]; c.Status != "unbound" || !strings.Contains(c.Reason, "carries the statement's payload hash") {
		t.Fatalf("%+v", c)
	}
	r = EvaluateExecutionEvidence([]ExecutionEntry{entries[0], entries[3]}, ExecutionEvaluationOptions{Policy: src.policy()})
	if c := r.Checks[0]; c.Status != "unbound" || !strings.Contains(c.Reason, "No Dispatch Record for this approval nonce") {
		t.Fatalf("%+v", c)
	}
	if n := r.ByNonce[testNonce]; n.Status != "not_reported" || n.DispatchSeq != nil || n.EffectiveDeadline != nil {
		t.Fatalf("%+v", n)
	}
}

func TestWindowIsBoundedByTheCaller(t *testing.T) {
	src := newEvidenceSource(t, "did:example:relay-7")
	farDeadline := plus(t0, 7*24*time.Hour)
	entries := []ExecutionEntry{
		approvalEntry("100"),
		dispatchEntry("101", t0, ExecutionPayloadSha256(testApprovalPayload), farDeadline),
		src.entry(t, "102", statementSpec{verdict: "confirmed", observedAt: plus(t0, 2*24*time.Hour), sequence: 1}),
	}
	now := atTime(plus(t0, 3*24*time.Hour))
	r := EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(), Now: now})
	n := r.ByNonce[testNonce]
	if r.Checks[0].Status != "stale" || !strings.Contains(r.Checks[0].Reason, "(late)") || n.Status != "unconfirmed" {
		t.Fatalf("default 24 h window: %+v %+v", r.Checks[0], n)
	}
	if !n.WindowCapped || *n.EffectiveDeadline != plus(t0, 24*time.Hour) || *n.EvidenceDeadline != farDeadline {
		t.Fatalf("%+v", n)
	}
	r = EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(), Now: now, MaxWindowSeconds: intp(10 * 86400)})
	if n := r.ByNonce[testNonce]; r.Checks[0].Status != "verified" || n.Status != "confirmed" || n.WindowCapped || *n.EffectiveDeadline != farDeadline {
		t.Fatalf("raised window: %+v %+v", r.Checks[0], n)
	}
	// A deadline exactly at the bound is not capped; one millisecond past the effective deadline is late.
	entries[1] = dispatchEntry("101", t0, ExecutionPayloadSha256(testApprovalPayload), plus(t0, 24*time.Hour))
	entries[2] = src.entry(t, "102", statementSpec{verdict: "confirmed", observedAt: plus(t0, 24*time.Hour+time.Millisecond), sequence: 1})
	r = EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(), Now: now})
	if n := r.ByNonce[testNonce]; n.WindowCapped || r.Checks[0].Status != "stale" {
		t.Fatalf("%+v %+v", r.Checks[0], n)
	}
	// The skew allowance is 30 s by default, evaluated on sampledAt, and caller-overridable.
	entries[2] = src.entry(t, "102", statementSpec{verdict: "confirmed", observedAt: plus(t0, time.Minute), sampledAt: plus(t0, -31*time.Second), sequence: 1})
	r = EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(), Now: atTime(plus(t0, time.Hour))})
	if c := r.Checks[0]; c.Status != "stale" || !strings.Contains(c.Reason, "(early)") || r.ByNonce[testNonce].Status != "pending" {
		t.Fatalf("%+v", c)
	}
	r = EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(), Now: atTime(plus(t0, time.Hour)), SkewSeconds: intp(60)})
	if c := r.Checks[0]; c.Status != "verified" {
		t.Fatalf("%+v", c)
	}
}

func TestLateContradictionIsItsOwnAlert(t *testing.T) {
	src := newEvidenceSource(t, "did:example:relay-7")
	late := statementSpec{verdict: "contradicted", observedAt: plus(t0, 2*time.Hour), sequence: 1}
	entries := []ExecutionEntry{
		approvalEntry("100"),
		dispatchEntry("101", t0, ExecutionPayloadSha256(testApprovalPayload), plus(t0, time.Hour)),
		src.entry(t, "102", late),
	}
	now := atTime(plus(t0, 3*time.Hour))
	r := EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(), Now: now})
	n := r.ByNonce[testNonce]
	if r.Checks[0].Status != "stale" || n.Status != "unconfirmed" || !reflect.DeepEqual(n.LateContradiction, []string{"102"}) || !reflect.DeepEqual(r.LateContradicted, []string{testNonce}) {
		t.Fatalf("the window rule stands, and the trusted contradiction is reported on its own: %+v %+v", r.Checks[0], n)
	}
	// Untrusted, early, confirmed and unbound late statements raise no alert.
	for name, variant := range map[string]struct {
		entries []ExecutionEntry
		policy  *ExecutionEvidencePolicy
	}{
		"untrusted": {entries, nil},
		"early":     {[]ExecutionEntry{entries[0], entries[1], src.entry(t, "102", statementSpec{verdict: "contradicted", observedAt: plus(t0, -time.Hour), sequence: 1})}, src.policy()},
		"confirmed": {[]ExecutionEntry{entries[0], entries[1], src.entry(t, "102", statementSpec{verdict: "confirmed", observedAt: plus(t0, 2*time.Hour), sequence: 1})}, src.policy()},
		"unbound":   {[]ExecutionEntry{entries[1], entries[2]}, src.policy()},
	} {
		r := EvaluateExecutionEvidence(variant.entries, ExecutionEvaluationOptions{Policy: variant.policy, Now: now})
		if len(r.LateContradicted) != 0 || len(r.ByNonce[testNonce].LateContradiction) != 0 {
			t.Errorf("%s: %+v", name, r.ByNonce[testNonce])
		}
	}
}

func TestSourceContinuityReportsGapsAndDivergence(t *testing.T) {
	src := newEvidenceSource(t, "did:example:relay-7")
	when := plus(t0, time.Minute)
	entries := []ExecutionEntry{
		approvalEntry("100"),
		dispatchEntry("101", t0, ExecutionPayloadSha256(testApprovalPayload), plus(t0, time.Hour)),
		src.entry(t, "102", statementSpec{verdict: "confirmed", observedAt: when, sequence: 1}),
		src.entry(t, "103", statementSpec{verdict: "confirmed", observedAt: when, sequence: 2}),
		src.entry(t, "104", statementSpec{verdict: "confirmed", observedAt: when, sequence: 5}),
		// Same counter value, different bytes: a divergence — even though this one is unbound.
		src.entry(t, "105", statementSpec{verdict: "confirmed", observedAt: when, sequence: 2, hash: strings.Repeat("b", 64)}),
	}
	// Identical bytes under one counter value are a re-export, not a divergence.
	entries = append(entries, ExecutionEntry{"106", entries[2].Leaf})
	r := EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(), Now: atTime(plus(t0, 2*time.Minute))})
	want := map[string]SourceContinuity{src.did: {First: 1, Last: 5, Gaps: [][2]int64{{3, 4}}, Divergent: []int64{2}}}
	if !reflect.DeepEqual(r.Sources, want) {
		t.Fatalf("%+v want %+v", r.Sources, want)
	}
	// A statement whose signature does not verify never advances the counter.
	tampered := src.entry(t, "107", statementSpec{verdict: "confirmed", observedAt: when, sequence: 9})
	tampered.Leaf.Signature = sp(base64.StdEncoding.EncodeToString(make([]byte, 64)))
	r = EvaluateExecutionEvidence(append(entries, tampered), ExecutionEvaluationOptions{Policy: src.policy(), Now: atTime(plus(t0, 2*time.Minute))})
	if r.Sources[src.did].Last != 5 || r.Checks[5].Status != "invalid" {
		t.Fatalf("%+v %+v", r.Sources, r.Checks[5])
	}
	// A source seen once has no range to check.
	r = EvaluateExecutionEvidence(entries[:3], ExecutionEvaluationOptions{Policy: src.policy()})
	if c := r.Sources[src.did]; c.First != 1 || c.Last != 1 || len(c.Gaps) != 0 || len(c.Divergent) != 0 {
		t.Fatalf("%+v", c)
	}
	if len(EvaluateExecutionEvidence(entries[:2], ExecutionEvaluationOptions{}).Sources) != 0 {
		t.Fatal("no statements, no sources")
	}
}

func TestBoundedKeyEstablishesTrustOnlyAtTheAnchoredTime(t *testing.T) {
	src := newEvidenceSource(t, "did:example:relay-7")
	entries := []ExecutionEntry{
		approvalEntry("100"),
		dispatchEntry("101", t0, ExecutionPayloadSha256(testApprovalPayload), plus(t0, time.Hour)),
		src.entry(t, "102", statementSpec{verdict: "confirmed", observedAt: plus(t0, time.Minute), sequence: 1}),
	}
	bounded := TrustedSourceKey{Key: src.spki, NotBefore: sp("2026-10-01T00:00:00.000Z"), NotAfter: sp("2026-10-07T00:00:00.000Z")}
	anchored := func(ms int64) func(string) (int64, bool) {
		return func(seq string) (int64, bool) { return ms, seq == "102" }
	}
	cases := []struct {
		name         string
		keys         []TrustedSourceKey
		anchoredTime func(string) (int64, bool)
		trusted      bool
		reason       string
	}{
		{"no anchored time", []TrustedSourceKey{bounded}, nil, false, "cannot be placed in time"},
		{"inside the interval", []TrustedSourceKey{bounded}, anchored(atTime("2026-10-05T23:59:00Z").UnixMilli()), true, "Statement verified"},
		{"after notAfter", []TrustedSourceKey{bounded}, anchored(atTime("2026-10-08T00:00:00Z").UnixMilli()), false, "not valid at this record's anchored time"},
		{"before notBefore", []TrustedSourceKey{bounded}, anchored(atTime("2026-09-30T00:00:00Z").UnixMilli()), false, "not valid at this record's anchored time"},
		{"inclusive bound", []TrustedSourceKey{bounded}, anchored(atTime("2026-10-07T00:00:00Z").UnixMilli()), true, "Statement verified"},
		{"malformed interval", []TrustedSourceKey{{Key: src.spki, NotAfter: sp("soon")}}, anchored(atTime("2026-10-05T23:59:00Z").UnixMilli()), false, "malformed validity interval"},
		{"bare key beside a bounded one", []TrustedSourceKey{{Key: src.spki, NotAfter: sp("2026-10-01T00:00:00.000Z")}, {Key: src.spki}}, nil, true, "Statement verified"},
		// The source's own timestamps never place the key: the statement is inside the interval, the anchor is not.
		{"observedAt is never used", []TrustedSourceKey{bounded}, anchored(atTime("2026-10-08T00:00:00Z").UnixMilli()), false, "DEWP §4.7.5"},
	}
	for _, c := range cases {
		r := EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(c.keys...), Now: atTime(plus(t0, 2*time.Minute)), AnchoredTime: c.anchoredTime})
		check := r.Checks[0]
		if check.Status != "verified" || check.Trusted != c.trusted || !strings.Contains(check.Reason, c.reason) {
			t.Errorf("%s: %+v", c.name, check)
		}
		wantStatus := "pending"
		if c.trusted {
			wantStatus = "confirmed"
		}
		if r.ByNonce[testNonce].Status != wantStatus {
			t.Errorf("%s: status %s want %s", c.name, r.ByNonce[testNonce].Status, wantStatus)
		}
	}
	// A single proof with a counting anchor places the key too; without one it cannot.
	leaf := entries[2].Leaf
	inside := atTime("2026-10-05T23:59:00Z").UnixMilli()
	if c := CheckExecutionEvidenceLeaf(leaf, src.policy(bounded), &inside); c.Status != "unbound" || !c.Trusted {
		t.Errorf("%+v", c)
	}
	if c := CheckExecutionEvidenceLeaf(leaf, src.policy(bounded), nil); c.Status != "unbound" || c.Trusted || !strings.Contains(c.Reason, "cannot be placed in time") {
		t.Errorf("%+v", c)
	}
	// The §4.6.1 signature check places a bounded key at the same anchored time the statement check
	// uses (DEWP §4.7.5), so the two reports agree: no anchored time, no trust; inside, trust.
	if s := VerifyAuditSignatureWithEvidence(leaf, nil, src.policy(bounded), nil); s.Status != "verified" || s.Trusted || !strings.Contains(s.Reason, "cannot be placed in time") {
		t.Errorf("%+v", s)
	}
	if s := VerifyAuditSignatureWithEvidence(leaf, nil, src.policy(bounded), &inside); s.Status != "verified" || !s.Trusted {
		t.Errorf("%+v", s)
	}
	outside := atTime("2026-10-08T00:00:00Z").UnixMilli()
	if s := VerifyAuditSignatureWithEvidence(leaf, nil, src.policy(bounded), &outside); s.Status != "verified" || s.Trusted || !strings.Contains(s.Reason, "not valid at this record's anchored time") {
		t.Errorf("%+v", s)
	}
	if s := VerifyAuditSignatureWithEvidence(leaf, nil, src.policy(), nil); s.Status != "verified" || !s.Trusted {
		t.Errorf("%+v", s)
	}
	// The two-argument form has no evidence policy and so no key to place in time.
	if s := VerifyAuditSignature(leaf, nil); s.Status != "verified" || s.Trusted {
		t.Errorf("%+v", s)
	}
}

func TestEveryApprovalRecordNonceIsEnumerated(t *testing.T) {
	src := newEvidenceSource(t, "did:example:relay-7")
	otherApproval := `{"nonce":"n-2","type":"div-intent-verification","v":1}`
	entries := []ExecutionEntry{
		approvalEntry("100"),
		{"101", AuditLeaf{Seq: sp("101"), CreatedAt: sp(t0), Event: sp("AUTHZ_APPROVED"), Outcome: sp("SUCCESS"), SignedPayload: sp(otherApproval)}},
		dispatchEntry("102", t0, ExecutionPayloadSha256(testApprovalPayload), plus(t0, time.Hour)),
		src.entry(t, "103", statementSpec{verdict: "confirmed", observedAt: plus(t0, time.Minute), sequence: 1}),
		// A payload that does not parse under §4.7.7 names no nonce.
		{"104", AuditLeaf{Seq: sp("104"), CreatedAt: sp(t0), Event: sp("AUTHZ_APPROVED"), Outcome: sp("SUCCESS"), SignedPayload: sp(`{"nonce":"n-3","type":"div-intent-verification","v":1} x`)}},
	}
	r := EvaluateExecutionEvidence(entries, ExecutionEvaluationOptions{Policy: src.policy(), Now: atTime(plus(t0, 2*time.Minute))})
	if len(r.ByNonce) != 2 || r.ByNonce["n-1"].Status != "confirmed" || r.ByNonce["n-2"].Status != "not_reported" {
		t.Fatalf("%+v", r.ByNonce)
	}
	if !reflect.DeepEqual(r.NotReported, []string{"n-2"}) || !reflect.DeepEqual(r.Confirmed, []string{"n-1"}) {
		t.Fatalf("%+v", r)
	}
	if n := r.ByNonce["n-2"]; n.DispatchSeq != nil || n.EffectiveDeadline != nil || n.WindowCapped || len(n.DispatchConflict) != 0 || len(n.LateContradiction) != 0 || len(n.EvidenceSeqs) != 0 {
		t.Fatalf("%+v", n)
	}
}
