package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// goldenDoc mirrors the parts of packages/mcp-schemas/vectors/canonical-vectors.json we consume.
type goldenDoc struct {
	// StableStringify pins the canonicalizer itself. This port implements its own StableStringify
	// but never checked it against the shared file, which is how Go's default HTML escaping of
	// <, > and & went unnoticed: the receipts below happen to contain none of those characters.
	StableStringify []struct {
		Name     string          `json:"name"`
		Value    json.RawMessage `json:"value"`
		Expected string          `json:"expected"`
	} `json:"stableStringify"`
	Receipts []struct {
		Name     string          `json:"name"`
		Receipt  ApprovalReceipt `json:"receipt"`
		ExpectOK bool            `json:"expectOk"`
	} `json:"receipts"`
}

// TestSharedStableStringifyVectors runs the canonicalizer against the same cases the TypeScript and
// Python suites use. Any divergence here means a signature produced by one implementation fails to
// verify under another and reads as tampering.
func TestSharedStableStringifyVectors(t *testing.T) {
	path := filepath.Join("vectors", "canonical-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read canonical vectors: %v", err)
	}
	var doc goldenDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse canonical vectors: %v", err)
	}
	if len(doc.StableStringify) == 0 {
		t.Fatal("canonical-vectors.json carries no stableStringify cases")
	}
	for _, c := range doc.StableStringify {
		// interface{} is the point, not an oversight. StableStringify(v interface{}) implements RFC
		// 8785 JCS over ARBITRARY JSON, and these vectors deliberately span objects, arrays, strings,
		// numbers, nulls, nested structures and non-ASCII keys. A concrete struct could not express
		// the input domain, and pinning one would stop the test exercising what it exists to pin.
		//
		// The CWE-502 shape the rule targets does not apply: the input is a committed in-repo vector
		// file, not untrusted input, and encoding/json into interface{} yields only map, slice,
		// string, float64, bool or nil. It instantiates no caller-named types, so there is no gadget
		// chain of the kind gob or type-tagged YAML permits.
		// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface
		var v interface{}
		if err := json.Unmarshal(c.Value, &v); err != nil {
			t.Errorf("%s: unmarshal value: %v", c.Name, err)
			continue
		}
		got, err := StableStringify(v)
		if err != nil {
			t.Errorf("StableStringify[%s] refused a portable vector value: %v", c.Name, err)
			continue
		}
		if got != c.Expected {
			t.Errorf("StableStringify[%s] =\n  %s\nwant\n  %s", c.Name, got, c.Expected)
		}
	}
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
		// Pinning the REASON, not just the refusal: `0 >= 0` makes DIV §5 step 7 true with nothing
		// counted, so this receipt can be refused for the right rule or for none at all.
		if entry.Name == "zero-required-approvals-refused" &&
			!strings.Contains(result.Reason, "requiredApprovals must be an integer of at least 1") {
			t.Errorf("vector %q: refused for the wrong rule (reason=%q)", entry.Name, result.Reason)
		}
		checked++
	}
	if checked < 3 {
		t.Fatalf("expected to exercise the current-version vectors, ran %d", checked)
	}
}

// payloadDoc mirrors the canonical-payload halves of the golden vectors: ordinary intent,
// offline approval and delegation.
type payloadDoc struct {
	IntentPayloads []struct {
		Input struct {
			Target            string                 `json:"target"`
			Nonce             string                 `json:"nonce"`
			ActionType        string                 `json:"actionType"`
			ActionDescription string                 `json:"actionDescription"`
			Params            map[string]interface{} `json:"params"`
			Requester         RequesterIdentity      `json:"requester"`
			Requirement       ApprovalRequirement    `json:"requirement"`
			ExpiresAt         string                 `json:"expiresAt"`
		} `json:"input"`
		Expected string `json:"expected"`
	} `json:"intentPayloads"`
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

func loadPayloadDoc(t *testing.T) payloadDoc {
	t.Helper()
	path := filepath.Join("vectors", "canonical-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden vectors: %v", err)
	}
	var doc payloadDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse golden vectors: %v", err)
	}
	return doc
}

// TestIntentCanonicalParity pins the ORDINARY intent payload against the shared vectors — the same
// cases the TS and Python suites consume, and the authoritative pin for this builder.
// verify_test.go keeps a hardcoded-literal pin of the same builder as a generator-independent
// backstop; see the comment there.
func TestIntentCanonicalParity(t *testing.T) {
	doc := loadPayloadDoc(t)
	if len(doc.IntentPayloads) == 0 {
		t.Fatal("no intent-payload vectors present")
	}
	for _, c := range doc.IntentPayloads {
		got, err := CanonicalIntentPayload(
			c.Input.Target,
			c.Input.ActionType,
			c.Input.ActionDescription,
			c.Input.Params,
			c.Input.Requester,
			c.Input.Requirement,
			c.Input.Nonce,
			c.Input.ExpiresAt,
		)
		if err != nil {
			t.Errorf("intent vector %s refused: %v", c.Input.ActionType, err)
			continue
		}
		if got != c.Expected {
			t.Errorf("intent vector drift for %s:\n got  %s\n want %s", c.Input.ActionType, got, c.Expected)
		}
		if !strings.Contains(got, `"type":"div-intent-verification"`) {
			t.Errorf("payload for %s is missing the intent type discriminator", c.Input.ActionType)
		}
	}
}

// TestOfflineCanonicalParity pins the OFFLINE APPROVAL canonicalization against the shared vectors.
//
// The receipts test above exercises verification; this one pins the byte output, which is where a port
// silently diverges. A Go build emitting different bytes could not verify an approval any TypeScript
// relying party produced — and the failure would look like tampering rather than drift.
func TestOfflineCanonicalParity(t *testing.T) {
	doc := loadPayloadDoc(t)
	if len(doc.OfflineIntentPayloads) == 0 {
		t.Fatal("no offline-approval vectors present")
	}
	for _, c := range doc.OfflineIntentPayloads {
		got, err := CanonicalOfflineIntentPayload(
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
		if err != nil {
			t.Errorf("offline vector %s refused: %v", c.Input.ActionType, err)
			continue
		}
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
	doc := loadPayloadDoc(t)
	if len(doc.DelegationPayloads) == 0 {
		t.Fatal("no delegation vectors present")
	}
	for _, c := range doc.DelegationPayloads {
		got, err := CanonicalDelegationPayload(
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
		if err != nil {
			t.Errorf("delegation vector %s refused: %v", c.Input.ActionType, err)
			continue
		}
		if got != c.Expected {
			t.Errorf("delegation vector drift for %s:\n got  %s\n want %s", c.Input.ActionType, got, c.Expected)
		}
		if !strings.Contains(got, `"type":"div-delegation"`) {
			t.Errorf("payload for %s is missing the delegation type discriminator", c.Input.ActionType)
		}
		// UTF-16 code-unit order: U+1F600 before U+FFFD. UTF-8-byte order (Go's sort.Strings) would
		// put them the other way round, so this line is what pins the comparator, not merely "sorted".
		if !strings.Contains(got, `"delegatedTo":["did:intyga:sre-a","did:intyga:sre-c","did:intyga:sre-😀","did:intyga:sre-�"]`) {
			t.Errorf("delegatedTo was not canonicalized as a sorted set for %s: %s", c.Input.ActionType, got)
		}
	}
}

// TestOfflineKindsNeverCollide pins the property that matters more than parity: the payload kinds must
// never produce the same bytes for the same action. If they could, an out-of-band approval would be
// indistinguishable from a gateway-mediated one, and an ordinary approval could be replayed as offline.
func TestOfflineKindsNeverCollide(t *testing.T) {
	doc := loadPayloadDoc(t)
	for _, c := range doc.OfflineIntentPayloads {
		offline, err := CanonicalOfflineIntentPayload(
			c.Input.Target, c.Input.ActionType, c.Input.ActionDescription, c.Input.Params,
			c.Input.Requester, c.Input.Requirement, c.Input.Nonce, c.Input.ChallengedAt, c.Input.ExpiresAt,
		)
		if err != nil {
			t.Fatalf("offline payload for %s refused: %v", c.Input.ActionType, err)
		}
		intent, err := CanonicalIntentPayload(
			c.Input.Target, c.Input.ActionType, c.Input.ActionDescription, c.Input.Params,
			c.Input.Requester, c.Input.Requirement, c.Input.Nonce, c.Input.ExpiresAt,
		)
		if err != nil {
			t.Fatalf("intent payload for %s refused: %v", c.Input.ActionType, err)
		}
		if offline == intent {
			t.Errorf("offline and intent payloads collide for %s", c.Input.ActionType)
		}
	}
}

// ─── Shared receipt suites (quorum / offline / delegation) ──────────────────
// The sections below were added to the golden vectors so the VERIFICATION behaviors — distinct-
// identity quorum counting, the offline opt-in and its 60-minute cap, delegation sealing and its
// 72-hour cap — are pinned by the same committed artifact in every port, not just canonicalization.
// documentPayloads is deliberately NOT consumed here: its note marks it TS-only (document signing
// is a gateway-side ceremony, not part of the relying-party offline surface this port implements).

// approverEntry is one row of a vector suite's identity → keys table.
type approverEntry struct {
	DID  string   `json:"did"`
	Keys []string `json:"keys"`
}

// receiptSuitesDoc mirrors the receipt-suite sections of canonical-vectors.json.
type receiptSuitesDoc struct {
	SignerKey struct {
		SpkiB64 string `json:"spkiB64"`
	} `json:"signerKey"`
	QuorumReceipts struct {
		Approvers []approverEntry `json:"approvers"`
		Cases     []struct {
			Name                 string          `json:"name"`
			Receipt              ApprovalReceipt `json:"receipt"`
			ExpectOk             bool            `json:"expectOk"`
			ExpectSigners        []string        `json:"expectSigners"`
			ExpectReasonIncludes string          `json:"expectReasonIncludes"`
		} `json:"cases"`
	} `json:"quorumReceipts"`
	OfflineReceipts []struct {
		Name    string          `json:"name"`
		Receipt ApprovalReceipt `json:"receipt"`
		// AsOf is the evaluation time (DIV §5a.3 rule 3). A harness that drops it silently accepts
		// the forward-dated case — which is exactly what this field exists to catch.
		AsOf                string `json:"asOf"`
		ExpectOkWithOptIn   bool   `json:"expectOkWithOptIn"`
		RefusedWithoutOptIn bool   `json:"refusedWithoutOptIn"`
	} `json:"offlineReceipts"`
	DelegationReceipts struct {
		Approvers []approverEntry `json:"approvers"`
		Cases     []struct {
			Name            string          `json:"name"`
			Receipt         ApprovalReceipt `json:"receipt"`
			AsOf            string          `json:"asOf"`
			ExpectOk        bool            `json:"expectOk"`
			DelegatedTo     []string        `json:"delegatedTo"`
			DelegatedQuorum int             `json:"delegatedQuorum"`
		} `json:"cases"`
	} `json:"delegationReceipts"`
}

// mustAsOf resolves a case's committed evaluation time. Fatal rather than defaulted to now(): a
// missing asOf would silently restore the position-blind behaviour the vectors pin against.
func mustAsOf(t *testing.T, name, raw string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("%s: vector carries no usable asOf (%q): %v", name, raw, err)
	}
	return at
}

func loadReceiptSuites(t *testing.T) receiptSuitesDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("vectors", "canonical-vectors.json"))
	if err != nil {
		t.Fatalf("read golden vectors: %v", err)
	}
	var doc receiptSuitesDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse golden vectors: %v", err)
	}
	return doc
}

// didAnchor builds a DID-mode trust anchor from a suite's identity → keys table. ResolveKeys
// (multi-key) is the point: one committed identity holds TWO credentials, and the quorum cases pin
// that both count as ONE approver.
func didAnchor(approvers []approverEntry) ApproverTrustAnchor {
	dids := make([]string, 0, len(approvers))
	byDID := make(map[string][]string, len(approvers))
	for _, a := range approvers {
		dids = append(dids, a.DID)
		byDID[a.DID] = a.Keys
	}
	return ApproverTrustAnchor{
		DIDs:        dids,
		ResolveKeys: func(did string) []string { return byDID[did] },
	}
}

// expectationFor rebuilds the relying party's expectation from the receipt's echoes, exactly as the
// TS consumer does. Legitimate for a golden vector only: the committed file IS the out-of-band
// record a real relying party would hold, so reading target/params back from it is the resolution
// step, not a shortcut.
func expectationFor(receipt ApprovalReceipt, anchor ApproverTrustAnchor) Expected {
	target := ""
	if receipt.Target != nil {
		target = *receipt.Target
	}
	actionType := ""
	if receipt.ActionType != nil {
		actionType = *receipt.ActionType
	}
	params := receipt.Params
	if params == nil {
		params = map[string]interface{}{}
	}
	return Expected{
		Target:     target,
		Nonce:      canonicalNonce(receipt.CanonicalPayload),
		ActionType: actionType,
		Params:     params,
		Approvers:  anchor,
	}
}

// sortedCSV renders a string set order-insensitively for comparison and diagnostics.
func sortedCSV(items []string) string {
	c := append([]string(nil), items...)
	sort.Strings(c)
	return strings.Join(c, ",")
}

// TestSharedQuorumReceiptVectors pins that a quorum counts distinct approver IDENTITIES, never
// signature entries: one approver signing with two registered credentials is still one approval,
// and a four-eyes requester's own signature never counts.
func TestSharedQuorumReceiptVectors(t *testing.T) {
	doc := loadReceiptSuites(t)
	if len(doc.QuorumReceipts.Cases) == 0 {
		t.Fatal("canonical-vectors.json carries no quorumReceipts cases")
	}
	anchor := didAnchor(doc.QuorumReceipts.Approvers)
	for _, c := range doc.QuorumReceipts.Cases {
		res := VerifyApprovalReceipt(c.Receipt, expectationFor(c.Receipt, anchor), VerifyOptions{})
		if res.OK != c.ExpectOk {
			t.Errorf("%s: ok=%v want %v (reason=%q)", c.Name, res.OK, c.ExpectOk, res.Reason)
			continue
		}
		if c.ExpectSigners != nil && sortedCSV(res.Signers) != sortedCSV(c.ExpectSigners) {
			t.Errorf("%s: signers %q, want %q", c.Name, sortedCSV(res.Signers), sortedCSV(c.ExpectSigners))
		}
		if !c.ExpectOk && c.ExpectReasonIncludes != "" && !strings.Contains(res.Reason, c.ExpectReasonIncludes) {
			t.Errorf("%s: reason %q does not include %q", c.Name, res.Reason, c.ExpectReasonIncludes)
		}
	}
}

// TestSharedOfflineReceiptVectors pins the offline opt-in refusal and the 60-minute window cap
// against the committed receipts: a validly signed proof with an over-long signed window must fail
// even WITH the opt-in.
func TestSharedOfflineReceiptVectors(t *testing.T) {
	doc := loadReceiptSuites(t)
	if len(doc.OfflineReceipts) == 0 {
		t.Fatal("canonical-vectors.json carries no offlineReceipts cases")
	}
	anchor := ApproverTrustAnchor{PublicKeys: []string{doc.SignerKey.SpkiB64}}
	for _, c := range doc.OfflineReceipts {
		expected := expectationFor(c.Receipt, anchor)
		asOf := mustAsOf(t, c.Name, c.AsOf)
		withOptIn := VerifyApprovalReceipt(c.Receipt, expected, VerifyOptions{AllowOffline: true, AsOf: asOf})
		if withOptIn.OK != c.ExpectOkWithOptIn {
			t.Errorf("%s: ok=%v want %v (reason=%q)", c.Name, withOptIn.OK, c.ExpectOkWithOptIn, withOptIn.Reason)
		}
		if c.RefusedWithoutOptIn {
			if without := VerifyApprovalReceipt(c.Receipt, expected, VerifyOptions{AsOf: asOf}); without.OK {
				t.Errorf("%s must be refused without the offline opt-in", c.Name)
			}
		}
		// The forward-dating rule is outside AllowExpired's reach: that override re-examines a proof
		// that WAS valid and has lapsed, which says nothing about one dated in the future.
		if c.Name == "offline-forward-dated-refused" {
			audit := VerifyApprovalReceipt(c.Receipt, expected,
				VerifyOptions{AllowOffline: true, AllowExpired: true, AsOf: asOf})
			if audit.OK || !strings.Contains(audit.Reason, "challenged in the future") {
				t.Errorf("%s: audit override must not rescue a forward-dated proof (ok=%v reason=%q)",
					c.Name, audit.OK, audit.Reason)
			}
		}
	}
}

// TestSharedDelegationReceiptVectors pins delegation sealing (ordinary quorum signs away approval
// authority) and the 72-hour window cap, and that the accepted delegation reports the committed
// operator set and quorum.
func TestSharedDelegationReceiptVectors(t *testing.T) {
	doc := loadReceiptSuites(t)
	if len(doc.DelegationReceipts.Cases) == 0 {
		t.Fatal("canonical-vectors.json carries no delegationReceipts cases")
	}
	anchor := didAnchor(doc.DelegationReceipts.Approvers)
	for _, c := range doc.DelegationReceipts.Cases {
		res, delegation := VerifyDelegation(c.Receipt, expectationFor(c.Receipt, anchor),
			VerifyOptions{AsOf: mustAsOf(t, c.Name, c.AsOf)})
		if res.OK != c.ExpectOk {
			t.Errorf("%s: ok=%v want %v (reason=%q)", c.Name, res.OK, c.ExpectOk, res.Reason)
			continue
		}
		if !c.ExpectOk {
			if delegation != nil {
				t.Errorf("%s: a refused delegation must not return a VerifiedDelegation", c.Name)
			}
			continue
		}
		if delegation == nil {
			t.Errorf("%s: accepted delegation is missing its VerifiedDelegation", c.Name)
			continue
		}
		if sortedCSV(delegation.DelegatedTo) != sortedCSV(c.DelegatedTo) {
			t.Errorf("%s: delegatedTo %q, want %q", c.Name, sortedCSV(delegation.DelegatedTo), sortedCSV(c.DelegatedTo))
		}
		if delegation.DelegatedQuorum != c.DelegatedQuorum {
			t.Errorf("%s: delegatedQuorum %d, want %d", c.Name, delegation.DelegatedQuorum, c.DelegatedQuorum)
		}
	}
}
