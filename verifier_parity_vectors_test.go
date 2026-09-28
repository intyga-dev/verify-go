package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type parityKey struct{ ID, DID, SpkiB64, CoseB64 string }
type parityCase struct {
	Name              string
	Receipt           ApprovalReceipt
	Bundle            json.RawMessage
	Entries           []RootsChainEntry
	Expected          map[string]interface{}
	Options           map[string]interface{}
	Policy            *AnchorPolicy
	OK                bool
	VerifiedCount     *int
	BrokenAt          int
	Unchained         bool
	VerificationLevel string
	Properties        map[string]bool
	Total             *int
	ContentVerified   *int
	CommitmentOnly    *int
	Signers           []string
	ActionPatterns    []string
	ReasonIncludes    string
	WitnessTimes      map[string]int64
	// "cose": the case's WEBAUTHN witness verifies under the key's COSE_Key, not its SPKI.
	ApproverKeyEncoding string
}
type paritySection struct {
	Expected map[string]interface{}
	Options  map[string]interface{}
	Cases    []parityCase
}
type parityDoc struct {
	Keys           []parityKey
	Approvals      paritySection
	Platform       paritySection
	AgentAuthority paritySection
	Bundles        struct {
		AnchorPolicy AnchorPolicy
		Cases        []parityCase
	}
	Evidence              struct{ Cases []parityCase }
	RootsChain            struct{ Cases []parityCase }
	DewpEvidenceHardening struct {
		Keys     []parityKey
		Bundles  struct{ Cases []parityCase }
		Evidence struct{ Cases []parityCase }
	}
	VerifierInputHardening struct {
		Keys           []parityKey
		Approvals      paritySection
		Platform       paritySection
		AgentAuthority paritySection
		Bundles        struct{ Cases []parityCase }
	}
}

func loadParity(t *testing.T) parityDoc {
	b, e := os.ReadFile(filepath.Join("vectors", "verifier-parity-vectors.json"))
	if e != nil {
		t.Fatal(e)
	}
	var d parityDoc
	if json.Unmarshal(b, &d) != nil {
		t.Fatal("invalid parity fixture")
	}
	return d
}
func mapMerge(a, b map[string]interface{}) map[string]interface{} {
	r := map[string]interface{}{}
	for k, v := range a {
		r[k] = v
	}
	for k, v := range b {
		r[k] = v
	}
	return r
}
func optTime(m map[string]interface{}) VerifyOptions {
	o := VerifyOptions{}
	if s, ok := m["expectedOrigin"].(string); ok {
		o.ExpectedOrigin = s
	}
	if s, ok := m["expectedRpId"].(string); ok {
		o.ExpectedRpID = s
	}
	if s, ok := m["asOf"].(string); ok {
		o.AsOf, _ = time.Parse(time.RFC3339, s)
	}
	if f, ok := m["clockSkewSeconds"].(float64); ok {
		x := int(f)
		o.ClockSkewSeconds = &x
	}
	if b, ok := m["allowOffline"].(bool); ok {
		o.AllowOffline = b
	}
	if b, ok := m["requireUserVerification"].(bool); ok {
		o.RequireUserVerification = &b
	}
	return o
}

// The fixture pins more than the boolean verdict: a refusal that lands for the wrong reason, or an
// acceptance that credits the wrong identities, is exactly the divergence these vectors exist to
// catch. Every optional field a case carries is asserted in every port.
func checkSigners(t *testing.T, c parityCase, got []string) {
	t.Helper()
	if c.Signers == nil {
		return
	}
	if len(got) == 0 {
		got = nil
	}
	if !reflect.DeepEqual(got, c.Signers) {
		t.Errorf("%s: signers %v, want %v", c.Name, got, c.Signers)
	}
}
func checkReason(t *testing.T, c parityCase, reason string) {
	t.Helper()
	if c.ReasonIncludes != "" && !strings.Contains(reason, c.ReasonIncludes) {
		t.Errorf("%s: reason %q does not contain %q", c.Name, reason, c.ReasonIncludes)
	}
}

// parityFloor reads a case's optional RP-supplied requirement floor (DIV §5 step 3d).
func parityFloor(raw map[string]interface{}) *RequirementFloor {
	m, ok := raw["requirement"].(map[string]interface{})
	if !ok {
		return nil
	}
	f := &RequirementFloor{}
	if n, ok := m["requiredApprovals"].(float64); ok {
		f.RequiredApprovals = int(n)
	}
	f.RequesterCannotApprove, _ = m["requesterCannotApprove"].(bool)
	f.RequireHardwareKey, _ = m["requireHardwareKey"].(bool)
	return f
}
func checkInt(t *testing.T, name, field string, want *int, got int) {
	t.Helper()
	if want != nil && got != *want {
		t.Errorf("%s: %s %d, want %d", name, field, got, *want)
	}
}
func TestVerifierParityVectors(t *testing.T) {
	d := loadParity(t)
	keys := map[string]parityKey{}
	for _, k := range d.Keys {
		keys[k.ID] = k
	}
	t.Run("approvals", func(t *testing.T) { runApprovalCases(t, d.Approvals, keys) })
	t.Run("platform", func(t *testing.T) { runPlatformCases(t, d.Platform, keys) })
	t.Run("authority", func(t *testing.T) { runAuthorityCases(t, d.AgentAuthority, keys) })
	t.Run("bundles", func(t *testing.T) { runBundleCases(t, d.Bundles.Cases, keys, &d.Bundles.AnchorPolicy) })
	t.Run("evidence", func(t *testing.T) { runEvidenceCases(t, d.Evidence.Cases, keys) })
	t.Run("dewpEvidenceHardening", func(t *testing.T) {
		h := d.DewpEvidenceHardening
		if len(h.Bundles.Cases) == 0 || len(h.Evidence.Cases) == 0 {
			t.Fatal("missing dewpEvidenceHardening section")
		}
		own := map[string]parityKey{}
		for _, k := range h.Keys {
			own[k.ID] = k
		}
		runBundleCases(t, h.Bundles.Cases, own, nil)
		runEvidenceCases(t, h.Evidence.Cases, own)
	})
	t.Run("verifierInputHardening", func(t *testing.T) {
		h := d.VerifierInputHardening
		if len(h.Approvals.Cases) == 0 || len(h.Platform.Cases) == 0 || len(h.AgentAuthority.Cases) == 0 || len(h.Bundles.Cases) == 0 {
			t.Fatal("missing verifierInputHardening section")
		}
		own := map[string]parityKey{}
		for _, k := range h.Keys {
			own[k.ID] = k
		}
		runApprovalCases(t, h.Approvals, own)
		runPlatformCases(t, h.Platform, own)
		runAuthorityCases(t, h.AgentAuthority, own)
		runBundleCases(t, h.Bundles.Cases, own, nil)
	})
	t.Run("chain", func(t *testing.T) {
		for _, c := range d.RootsChain.Cases {
			r := VerifyRootsChain(c.Entries)
			if r.OK != c.OK || r.BrokenAt != c.BrokenAt || r.Unchained != c.Unchained {
				t.Errorf("%s: %+v", c.Name, r)
			}
			checkInt(t, c.Name, "verifiedCount", c.VerifiedCount, r.VerifiedCount)
		}
	})
}

func externalKeysFrom(o map[string]interface{}, keys map[string]parityKey) ExternalAnchorKeys {
	var x ExternalAnchorKeys
	if id, ok := o["rekorKeyId"].(string); ok {
		x.Rekor = keys[id].SpkiB64
	}
	if issuer, ok := o["rekorIssuer"].(string); ok {
		x.RekorIssuer = issuer
	}
	if ids, ok := o["rekorSubmitterKeyIds"].([]interface{}); ok {
		for _, id := range ids {
			x.RekorSubmitterKeys = append(x.RekorSubmitterKeys, keys[id.(string)].SpkiB64)
		}
	}
	return x
}

// runBundleCases: defaultPolicy is the `bundles` section's; the hardening section applies a policy only
// when a case carries one.
func runBundleCases(t *testing.T, cases []parityCase, keys map[string]parityKey, defaultPolicy *AnchorPolicy) {
	for _, c := range cases {
		var b ProofBundle
		if e := json.Unmarshal(c.Bundle, &b); e != nil {
			t.Fatal(e)
		}
		policy := defaultPolicy
		if c.Policy != nil {
			policy = c.Policy
		}
		o := BundleVerifyOptions{AnchorPolicy: policy, ResolveAnchorKey: func(a SignedAnchor) string { return keys[a.KeyID].SpkiB64 }}
		if v, ok := c.Options["trustedRoot"].(string); ok {
			o.TrustedRoot = v
		}
		if v, ok := c.Options["trustedCheckpoint"]; ok {
			raw, _ := json.Marshal(v)
			o.TrustedCheckpoint = &TrustedCheckpoint{}
			json.Unmarshal(raw, o.TrustedCheckpoint)
		}
		if v, ok := c.Options["divergenceAnchors"]; ok {
			raw, _ := json.Marshal(v)
			json.Unmarshal(raw, &o.Anchors)
		}
		o.ExternalKeys = externalKeysFrom(c.Options, keys)
		r := VerifyBundle(b, o)
		if r.OK != c.OK {
			t.Errorf("%s: got %v notes=%v", c.Name, r.OK, r.Notes)
		}
		if c.WitnessTimes != nil && !reflect.DeepEqual(r.WitnessTimes, c.WitnessTimes) {
			t.Errorf("%s: witnessTimes %v, want %v", c.Name, r.WitnessTimes, c.WitnessTimes)
		}
		if c.VerificationLevel != "" && r.VerificationLevel != c.VerificationLevel {
			t.Errorf("%s level %s", c.Name, r.VerificationLevel)
		}
		for key, want := range c.Properties {
			var got bool
			switch key {
			case "commitmentVerified":
				got = r.Properties.CommitmentVerified
			case "contentVerified":
				got = r.Properties.ContentVerified
			case "signatureVerified":
				got = r.Properties.SignatureVerified
			case "anchorVerified":
				got = r.Properties.AnchorVerified
			default:
				t.Fatalf("unknown property %s", key)
			}
			if got != want {
				t.Errorf("%s: properties.%s %v, want %v", c.Name, key, got, want)
			}
		}
	}
}

func runEvidenceCases(t *testing.T, cases []parityCase, keys map[string]parityKey) {
	for _, c := range cases {
		var b EvidenceBundle
		if e := json.Unmarshal(c.Bundle, &b); e != nil {
			t.Fatal(e)
		}
		o := EvidenceVerifyOptions{}
		if v, ok := c.Options["trustedRoots"]; ok {
			for _, x := range v.([]interface{}) {
				o.TrustedRoots = append(o.TrustedRoots, x.(string))
			}
		}
		if v, ok := c.Options["trustedCheckpoints"]; ok {
			raw, _ := json.Marshal(v)
			json.Unmarshal(raw, &o.TrustedCheckpoints)
		}
		o.AnchorPolicy = c.Policy
		if c.Policy != nil {
			o.ResolveAnchorKey = func(a SignedAnchor) string { return keys[a.KeyID].SpkiB64 }
		}
		if v, ok := c.Options["anchors"]; ok {
			raw, _ := json.Marshal(v)
			if _, keyed := v.(map[string]interface{}); keyed {
				json.Unmarshal(raw, &o.AnchorsByCheckpoint)
			} else {
				json.Unmarshal(raw, &o.Anchors)
			}
		}
		o.ExternalKeys = externalKeysFrom(c.Options, keys)
		r := VerifyEvidenceBundle(b, o)
		if r.OK != c.OK {
			t.Errorf("%s: got %v failures=%v notes=%v", c.Name, r.OK, r.Failed, r.Notes)
		}
		checkInt(t, c.Name, "total", c.Total, r.Total)
		checkInt(t, c.Name, "contentVerified", c.ContentVerified, r.ContentVerified)
		checkInt(t, c.Name, "commitmentOnly", c.CommitmentOnly, r.CommitmentOnly)
	}
}

func runApprovalCases(t *testing.T, sec paritySection, keys map[string]parityKey) {
	for _, c := range sec.Cases {
		raw := mapMerge(sec.Expected, c.Expected)
		pub := []string{}
		for _, id := range raw["approverKeyIds"].([]interface{}) {
			if c.ApproverKeyEncoding == "cose" {
				pub = append(pub, keys[id.(string)].CoseB64)
			} else {
				pub = append(pub, keys[id.(string)].SpkiB64)
			}
		}
		expected := Expected{Target: raw["target"].(string), Nonce: raw["nonce"].(string), ActionType: raw["actionType"].(string), Params: raw["params"].(map[string]interface{}), Approvers: ApproverTrustAnchor{PublicKeys: pub}, Requirement: parityFloor(raw)}
		if context, ok := raw["agentContext"].(map[string]interface{}); ok {
			expected.AgentContext = context
		}
		result := VerifyApprovalReceipt(c.Receipt, expected, optTime(mapMerge(sec.Options, c.Options)))
		if result.OK != c.OK {
			t.Errorf("%s: %v %s", c.Name, result.OK, result.Reason)
		}
		checkSigners(t, c, result.Signers)
		checkReason(t, c, result.Reason)
	}
}

func runPlatformCases(t *testing.T, sec paritySection, keys map[string]parityKey) {
	for _, c := range sec.Cases {
		raw := mapMerge(sec.Expected, c.Expected)
		ids := raw["approverKeyIds"].([]interface{})
		pub := []string{}
		for _, id := range ids {
			pub = append(pub, keys[id.(string)].CoseB64)
		}
		ex := PlatformReceiptExpectation{Approvers: ApproverTrustAnchor{PublicKeys: pub}, PayloadHash: raw["payloadHash"].(string), RpID: raw["rpId"].(string), Nonce: raw["nonce"].(string), SubjectExternalID: raw["subjectExternalId"].(string)}
		r := VerifyPlatformReceipt(c.Receipt, ex, optTime(mapMerge(sec.Options, c.Options)))
		if r.OK != c.OK {
			t.Errorf("%s: got %v %s", c.Name, r.OK, r.Reason)
		}
		checkSigners(t, c, r.Signers)
		checkReason(t, c, r.Reason)
	}
}

func runAuthorityCases(t *testing.T, sec paritySection, keys map[string]parityKey) {
	for _, c := range sec.Cases {
		raw := mapMerge(sec.Expected, c.Expected)
		table := raw["approverDids"].(map[string]interface{})
		dids := []string{}
		resolved := map[string][]string{}
		for did, v := range table {
			dids = append(dids, did)
			for _, id := range v.([]interface{}) {
				resolved[did] = append(resolved[did], keys[id.(string)].SpkiB64)
			}
		}
		a := ApproverTrustAnchor{DIDs: dids, ResolveKeys: func(did string) []string { return resolved[did] }}
		if ids, ok := raw["approverKeyIds"].([]interface{}); ok {
			a = ApproverTrustAnchor{}
			for _, id := range ids {
				a.PublicKeys = append(a.PublicKeys, keys[id.(string)].SpkiB64)
			}
		}
		ex := AgentAuthorityExpectation{Approvers: a, Target: raw["target"].(string), AgentDID: raw["agentDid"].(string), Requirement: parityFloor(raw)}
		r, authority := VerifyAgentAuthority(c.Receipt, ex, optTime(mapMerge(sec.Options, c.Options)))
		if r.OK != c.OK {
			t.Errorf("%s: got %v %s", c.Name, r.OK, r.Reason)
		}
		checkReason(t, c, r.Reason)
		if c.Signers != nil || c.ActionPatterns != nil {
			if authority == nil {
				t.Errorf("%s: no verified authority to inspect", c.Name)
				continue
			}
			checkSigners(t, c, authority.Signers)
			if c.ActionPatterns != nil && !reflect.DeepEqual(authority.ActionPatterns, c.ActionPatterns) {
				t.Errorf("%s: actionPatterns %v, want %v", c.Name, authority.ActionPatterns, c.ActionPatterns)
			}
		}
	}
}
