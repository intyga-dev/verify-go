package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
	// Reason, when present, is the exact refusal text every port must produce (after API-name
	// localization, apiNameHints).
	Reason          *string
	ReasonPrefix    *string
	Witness         map[string]interface{}
	Expectation     map[string]interface{}
	DelegatedTo     []string
	DelegatedQuorum *int
	WitnessTimes    map[string]int64
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
	Delegation            paritySection
	WebAuthnWitness       struct{ Cases []parityCase }
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
	// EnrolledDevice is DIV §4.3.2 "Enrolled approver devices", with its own keys.
	EnrolledDevice struct {
		Keys           []parityKey
		Approvals      paritySection
		Delegation     paritySection
		AgentAuthority paritySection
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
	if c.ReasonIncludes != "" && !strings.Contains(reason, localizedReason(t, c.ReasonIncludes)) {
		t.Errorf("%s: reason %q does not contain %q", c.Name, reason, localizedReason(t, c.ReasonIncludes))
	}
	if c.Reason != nil && reason != localizedReason(t, *c.Reason) {
		t.Errorf("%s: reason %q, want exactly %q", c.Name, reason, localizedReason(t, *c.Reason))
	}
}

// apiNameHints is packages/mcp-schemas/vectors/api-name-hints.json: vector reasons name the
// TypeScript API, and this port's refusal texts name Go's (VerifyOptions{AllowExpired: true},
// expected.Target, VerifyDelegation, ...). Everything else in a text is identical across ports.
type apiNameHints struct {
	Tokens []string          `json:"tokens"`
	Go     map[string]string `json:"go"`
}

func loadAPINameHints(t *testing.T) apiNameHints {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("vectors", "api-name-hints.json"))
	if err != nil {
		t.Fatal(err)
	}
	var h apiNameHints
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatal(err)
	}
	if len(h.Go) != len(h.Tokens) {
		t.Fatalf("api-name-hints go map has %d entries for %d tokens", len(h.Go), len(h.Tokens))
	}
	for _, token := range h.Tokens {
		if _, ok := h.Go[token]; !ok {
			t.Fatalf("api-name-hints go map lacks %q", token)
		}
	}
	return h
}

// localizedReason rewrites an expected reason: every token, longest first, becomes a placeholder,
// then every placeholder becomes Go's spelling — a single pass, so a value is never rescanned.
func localizedReason(t *testing.T, text string) string {
	t.Helper()
	h := loadAPINameHints(t)
	order := append([]string(nil), h.Tokens...)
	sort.SliceStable(order, func(i, j int) bool { return len(order[i]) > len(order[j]) })
	for i, token := range order {
		text = strings.ReplaceAll(text, token, fmt.Sprintf("\x00%d\x00", i))
	}
	for i, token := range order {
		text = strings.ReplaceAll(text, fmt.Sprintf("\x00%d\x00", i), h.Go[token])
	}
	return text
}

// parityFloor reads a case's optional RP-supplied requirement floor (DIV §5 step 3d).
func parityFloor(raw map[string]interface{}) *RequirementFloor {
	m, ok := raw["requirement"].(map[string]interface{})
	if !ok {
		return nil
	}
	f := &RequirementFloor{}
	// The boolean flags go through RequirementFloor's own JSON decoding, so a present non-boolean
	// flag ("yes", null) reaches the verifier as a malformed floor exactly as in the reference.
	flags := map[string]interface{}{}
	for _, key := range []string{"requesterCannotApprove", "requireHardwareKey", "requireEnrolledDevice"} {
		if value, present := m[key]; present {
			flags[key] = value
		}
	}
	encoded, _ := json.Marshal(flags)
	if err := json.Unmarshal(encoded, f); err != nil {
		panic(err)
	}
	if n, ok := m["requiredApprovals"].(float64); ok {
		f.RequiredApprovals = int(n)
	}
	if rawExcluded, present := m["excludedSignerDids"]; present {
		values, ok := rawExcluded.([]interface{})
		if !ok {
			return f
		}
		excluded := make([]string, 0, len(values))
		for _, value := range values {
			if did, ok := value.(string); ok {
				excluded = append(excluded, did)
			}
		}
		f.ExcludedSignerDIDs = &excluded
	}
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
	t.Run("delegation", func(t *testing.T) { runDelegationCases(t, d.Delegation, keys) })
	t.Run("webauthnWitness", func(t *testing.T) { runWebAuthnWitnessCases(t, d.WebAuthnWitness.Cases) })
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
	t.Run("enrolledDevice", func(t *testing.T) {
		h := d.EnrolledDevice
		if len(h.Approvals.Cases) == 0 || len(h.Delegation.Cases) == 0 || len(h.AgentAuthority.Cases) == 0 {
			t.Fatal("missing enrolledDevice section")
		}
		own := map[string]parityKey{}
		for _, k := range h.Keys {
			own[k.ID] = k
		}
		runApprovalCases(t, h.Approvals, own)
		runDelegationCases(t, h.Delegation, own)
		runAuthorityCases(t, h.AgentAuthority, own)
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
		anchor := ApproverTrustAnchor{}
		if table, ok := raw["approverDids"].(map[string]interface{}); ok {
			coseDids := map[string]bool{}
			if values, ok := raw["approverCoseDids"].([]interface{}); ok {
				for _, did := range values {
					coseDids[did.(string)] = true
				}
			}
			dids := []string{}
			resolved := map[string][]string{}
			for did, ids := range table {
				dids = append(dids, did)
				for _, rawID := range ids.([]interface{}) {
					key := keys[rawID.(string)]
					if coseDids[did] {
						resolved[did] = append(resolved[did], key.CoseB64)
					} else {
						resolved[did] = append(resolved[did], key.SpkiB64)
					}
				}
			}
			throwsFor := map[string]bool{}
			if values, ok := raw["resolverThrowsFor"].([]interface{}); ok {
				for _, did := range values {
					throwsFor[did.(string)] = true
				}
			}
			anchor = ApproverTrustAnchor{DIDs: dids, ResolveKeys: func(did string) []string {
				if throwsFor[did] {
					panic("resolver unavailable for " + did)
				}
				return resolved[did]
			}}
			if omitted, _ := raw["resolverOmitted"].(bool); omitted {
				// A DID-mode anchor with no resolver at all (neither ResolveKeys nor ResolveKey).
				anchor = ApproverTrustAnchor{DIDs: dids}
			}
		} else {
			pub := []string{}
			for _, id := range raw["approverKeyIds"].([]interface{}) {
				if c.ApproverKeyEncoding == "cose" {
					pub = append(pub, keys[id.(string)].CoseB64)
				} else {
					pub = append(pub, keys[id.(string)].SpkiB64)
				}
			}
			anchor = ApproverTrustAnchor{PublicKeys: pub}
		}
		expected := Expected{Target: raw["target"].(string), Nonce: raw["nonce"].(string), ActionType: raw["actionType"].(string), Params: raw["params"].(map[string]interface{}), Approvers: anchor, Requirement: parityFloor(raw)}
		if tenant, ok := raw["tenantId"].(string); ok {
			expected.TenantID = &tenant
		}
		if context, ok := raw["agentContext"].(map[string]interface{}); ok {
			expected.AgentContext = context
		}
		// enrolledDevice section: key ids map to SPKI; a literal list passes through verbatim.
		if ids, ok := raw["enrolledDeviceKeyIds"].([]interface{}); ok {
			expected.EnrolledDeviceKeys = []string{}
			for _, id := range ids {
				expected.EnrolledDeviceKeys = append(expected.EnrolledDeviceKeys, keys[id.(string)].SpkiB64)
			}
		} else if values, ok := raw["enrolledDeviceKeys"].([]interface{}); ok {
			expected.EnrolledDeviceKeys = []string{}
			for _, value := range values {
				expected.EnrolledDeviceKeys = append(expected.EnrolledDeviceKeys, value.(string))
			}
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
		if tenant, ok := raw["tenantId"].(string); ok {
			ex.TenantID = &tenant
		}
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
		if tenant, ok := raw["tenantId"].(string); ok {
			ex.TenantID = &tenant
		}
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

// DEWP §4.7 (version 1.1): the shared executionEvidence section, run exactly as TS runs it.
func TestExecutionEvidenceParityVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("vectors", "verifier-parity-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	type statusRow struct {
		Seq     string `json:"seq"`
		Status  string `json:"status"`
		Trusted bool   `json:"trusted"`
	}
	var doc struct {
		ExecutionEvidence struct {
			Cases []struct {
				Name   string          `json:"name"`
				Bundle json.RawMessage `json:"bundle"`
				// Policy is the anchor policy of the anchored-time cases (DEWP §4.7.5): the bundle's
				// checkpoint carries a Rekor-witnessed anchor and options.rekorSpki pins the log key.
				Policy  *AnchorPolicy `json:"policy"`
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
				OK              bool `json:"ok"`
				ContentVerified *int `json:"contentVerified"`
				CommitmentOnly  *int `json:"commitmentOnly"`
				Execution       struct {
					ByNonce  map[string]string `json:"byNonce"`
					Checks   []statusRow       `json:"checks"`
					Findings *struct {
						LateContradicted      *[]string                   `json:"lateContradicted"`
						UntrustedContradicted *[]string                   `json:"untrustedContradicted"`
						DispatchConflicts     *[]string                   `json:"dispatchConflicts"`
						WindowCapped          map[string]bool             `json:"windowCapped"`
						Sources               map[string]SourceContinuity `json:"sources"`
					} `json:"findings"`
				} `json:"execution"`
				Signatures []statusRow `json:"signatures"`
			} `json:"cases"`
			Proofs []struct {
				Name    string          `json:"name"`
				Bundle  json.RawMessage `json:"bundle"`
				Options struct {
					TrustedRoot    string                   `json:"trustedRoot"`
					EvidencePolicy *ExecutionEvidencePolicy `json:"evidencePolicy"`
				} `json:"options"`
				Execution *struct {
					Status  string `json:"status"`
					Trusted bool   `json:"trusted"`
				} `json:"execution"`
			} `json:"proofs"`
			Statements []struct {
				Name  string `json:"name"`
				Bytes string `json:"bytes"`
				OK    bool   `json:"ok"`
			} `json:"statements"`
			Builder []struct {
				Name  string `json:"name"`
				Input struct {
					Nonce         string                 `json:"nonce"`
					PayloadSha256 string                 `json:"payloadSha256"`
					Source        string                 `json:"source"`
					Verdict       string                 `json:"verdict"`
					ObservedAt    string                 `json:"observedAt"`
					SampledAt     string                 `json:"sampledAt"`
					Sequence      int64                  `json:"sequence"`
					Observation   map[string]interface{} `json:"observation"`
				} `json:"input"`
				Bytes string `json:"bytes"`
			} `json:"builder"`
		} `json:"executionEvidence"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	section := doc.ExecutionEvidence
	if len(section.Cases) == 0 || len(section.Proofs) == 0 {
		t.Fatal("executionEvidence section is empty")
	}
	for _, c := range section.Cases {
		var bundle EvidenceBundle
		if err := json.Unmarshal(c.Bundle, &bundle); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		now, err := time.Parse(time.RFC3339Nano, c.Options.Now)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		r := VerifyEvidenceBundle(bundle, EvidenceVerifyOptions{
			TrustedRoots: c.Options.TrustedRoots, EvidencePolicy: c.Options.EvidencePolicy,
			SignaturePolicy: c.Options.SignaturePolicy, ExecutionNow: &now, EvidenceSkewSeconds: c.Options.SkewSeconds,
			MaxEvidenceWindowSeconds: c.Options.MaxWindowSeconds, RequireExecutionConfirmed: c.Options.RequireExecutionConfirmed,
			AnchorPolicy: c.Policy, ExternalKeys: ExternalAnchorKeys{Rekor: c.Options.RekorSpki},
		})
		if r.OK != c.OK {
			t.Errorf("%s: ok=%v want %v (%v)", c.Name, r.OK, c.OK, r.Failed)
		}
		if c.ContentVerified != nil && r.ContentVerified != *c.ContentVerified {
			t.Errorf("%s: contentVerified=%d want %d", c.Name, r.ContentVerified, *c.ContentVerified)
		}
		if c.CommitmentOnly != nil && r.CommitmentOnly != *c.CommitmentOnly {
			t.Errorf("%s: commitmentOnly=%d want %d", c.Name, r.CommitmentOnly, *c.CommitmentOnly)
		}
		byNonce := map[string]string{}
		for n, v := range r.Execution.ByNonce {
			byNonce[n] = v.Status
		}
		if len(byNonce) != len(c.Execution.ByNonce) || (len(byNonce) > 0 && !reflect.DeepEqual(byNonce, c.Execution.ByNonce)) {
			t.Errorf("%s: byNonce %v want %v", c.Name, byNonce, c.Execution.ByNonce)
		}
		checks := []statusRow{}
		reasons := []string{}
		for _, k := range r.Execution.Checks {
			checks = append(checks, statusRow{k.Seq, k.Status, k.Trusted})
			reasons = append(reasons, k.Reason)
		}
		if len(checks) != len(c.Execution.Checks) || (len(checks) > 0 && !reflect.DeepEqual(checks, c.Execution.Checks)) {
			t.Errorf("%s: checks %v want %v (%v)", c.Name, checks, c.Execution.Checks, reasons)
		}
		// Every finding the case states is asserted; one it leaves out is not (DEWP §4.7.4).
		if f := c.Execution.Findings; f != nil {
			if f.LateContradicted != nil && !reflect.DeepEqual(r.Execution.LateContradicted, *f.LateContradicted) {
				t.Errorf("%s: lateContradicted %v want %v", c.Name, r.Execution.LateContradicted, *f.LateContradicted)
			}
			if f.UntrustedContradicted != nil && !reflect.DeepEqual(r.Execution.UntrustedContradicted, *f.UntrustedContradicted) {
				t.Errorf("%s: untrustedContradicted %v want %v", c.Name, r.Execution.UntrustedContradicted, *f.UntrustedContradicted)
			}
			if f.DispatchConflicts != nil && !reflect.DeepEqual(r.Execution.DispatchConflicts, *f.DispatchConflicts) {
				t.Errorf("%s: dispatchConflicts %v want %v", c.Name, r.Execution.DispatchConflicts, *f.DispatchConflicts)
			}
			if f.WindowCapped != nil {
				capped := map[string]bool{}
				for n, v := range r.Execution.ByNonce {
					capped[n] = v.WindowCapped
				}
				if !reflect.DeepEqual(capped, f.WindowCapped) {
					t.Errorf("%s: windowCapped %v want %v", c.Name, capped, f.WindowCapped)
				}
			}
			if f.Sources != nil && !reflect.DeepEqual(r.Execution.Sources, f.Sources) {
				t.Errorf("%s: sources %+v want %+v", c.Name, r.Execution.Sources, f.Sources)
			}
		}
		if c.Signatures != nil {
			sigs := []statusRow{}
			for _, k := range r.Signatures.Checks {
				sigs = append(sigs, statusRow{k.Seq, k.Status, k.Trusted})
			}
			if !reflect.DeepEqual(sigs, c.Signatures) {
				t.Errorf("%s: signatures %v want %v", c.Name, sigs, c.Signatures)
			}
		}
	}
	for _, c := range section.Proofs {
		var bundle ProofBundle
		if err := json.Unmarshal(c.Bundle, &bundle); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		r := VerifyBundle(bundle, BundleVerifyOptions{TrustedRoot: c.Options.TrustedRoot, EvidencePolicy: c.Options.EvidencePolicy})
		if !r.Properties.ContentVerified {
			t.Errorf("%s: not content-verified", c.Name)
		}
		switch {
		case c.Execution == nil && r.Execution != nil:
			t.Errorf("%s: unexpected execution %+v", c.Name, r.Execution)
		case c.Execution != nil && (r.Execution == nil || r.Execution.Status != c.Execution.Status || r.Execution.Trusted != c.Execution.Trusted):
			t.Errorf("%s: execution %+v want %+v", c.Name, r.Execution, c.Execution)
		}
	}
	for _, c := range section.Statements {
		_, err := ParseExecutionEvidenceStatement(c.Bytes)
		if (err == nil) != c.OK {
			t.Errorf("statement %s: ok=%v want %v (%v)", c.Name, err == nil, c.OK, err)
		}
	}
	for _, c := range section.Builder {
		got, err := CanonicalExecutionEvidenceStatement(ExecutionEvidenceStatement{
			Nonce: c.Input.Nonce, PayloadSha256: c.Input.PayloadSha256, Source: c.Input.Source,
			Verdict: c.Input.Verdict, ObservedAt: c.Input.ObservedAt, SampledAt: c.Input.SampledAt,
			Sequence: c.Input.Sequence, Observation: c.Input.Observation,
		})
		if err != nil || got != c.Bytes {
			t.Errorf("builder %s: %q (%v) want %q", c.Name, got, err, c.Bytes)
		}
	}
}

// runDelegationCases runs the seal verifier against a DID-mode anchor over expected.approverDids.
func runDelegationCases(t *testing.T, sec paritySection, keys map[string]parityKey) {
	if len(sec.Cases) == 0 {
		t.Fatal("missing delegation section")
	}
	for _, c := range sec.Cases {
		raw := mapMerge(sec.Expected, c.Expected)
		table := raw["approverDids"].(map[string]interface{})
		dids := []string{}
		resolved := map[string][]string{}
		for did, ids := range table {
			dids = append(dids, did)
			for _, id := range ids.([]interface{}) {
				resolved[did] = append(resolved[did], keys[id.(string)].SpkiB64)
			}
		}
		expected := Expected{
			Approvers:   ApproverTrustAnchor{DIDs: dids, ResolveKeys: func(did string) []string { return resolved[did] }},
			Requirement: parityFloor(raw),
		}
		expected.Target, _ = raw["target"].(string)
		expected.ActionType, _ = raw["actionType"].(string)
		expected.Params, _ = raw["params"].(map[string]interface{})
		expected.RequesterDID, _ = raw["requesterDid"].(string)
		if tenant, ok := raw["tenantId"].(string); ok {
			expected.TenantID = &tenant
		}
		r, d := VerifyDelegation(c.Receipt, expected, optTime(mapMerge(sec.Options, c.Options)))
		if r.OK != c.OK {
			t.Errorf("%s: got %v %s", c.Name, r.OK, r.Reason)
		}
		checkReason(t, c, r.Reason)
		if c.Signers != nil || c.DelegatedTo != nil || c.DelegatedQuorum != nil {
			if d == nil {
				t.Errorf("%s: no verified delegation to inspect", c.Name)
				continue
			}
			if c.Signers != nil && !reflect.DeepEqual(d.Signers, c.Signers) {
				t.Errorf("%s: signers %v, want %v", c.Name, d.Signers, c.Signers)
			}
			if c.DelegatedTo != nil && !reflect.DeepEqual(d.DelegatedTo, c.DelegatedTo) {
				t.Errorf("%s: delegatedTo %v, want %v", c.Name, d.DelegatedTo, c.DelegatedTo)
			}
			if c.DelegatedQuorum != nil && d.DelegatedQuorum != *c.DelegatedQuorum {
				t.Errorf("%s: delegatedQuorum %d, want %d", c.Name, d.DelegatedQuorum, *c.DelegatedQuorum)
			}
		}
	}
}

// runWebAuthnWitnessCases runs the standalone assertion check. An expectation field that is absent is
// omitted; a value the reference would not accept as a string becomes "", which Go refuses the same
// way (the reference reads any non-string as missing).
func runWebAuthnWitnessCases(t *testing.T, cases []parityCase) {
	if len(cases) == 0 {
		t.Fatal("missing webauthnWitness section")
	}
	text := func(m map[string]interface{}, key string) string {
		s, _ := m[key].(string)
		return s
	}
	for _, c := range cases {
		w := WebAuthnWitness{
			SignedPayload:     text(c.Witness, "signedPayload"),
			PublicKey:         text(c.Witness, "publicKey"),
			AuthenticatorData: text(c.Witness, "authenticatorData"),
			ClientDataJSON:    text(c.Witness, "clientDataJSON"),
			Signature:         text(c.Witness, "signature"),
		}
		var e WebAuthnWitnessExpectation
		switch origin := c.Expectation["expectedOrigin"].(type) {
		case nil:
		case string:
			e.ExpectedOrigin = []string{origin}
		case []interface{}:
			e.ExpectedOrigin = []string{}
			for _, o := range origin {
				s, _ := o.(string)
				e.ExpectedOrigin = append(e.ExpectedOrigin, s)
			}
		default:
			e.ExpectedOrigin = []string{""}
		}
		e.ExpectedRpID = text(c.Expectation, "expectedRpId")
		if uv, ok := c.Expectation["requireUserVerification"].(bool); ok {
			e.RequireUserVerification = &uv
		}
		e.AllowCrossOrigin, _ = c.Expectation["allowCrossOrigin"].(bool)
		r := VerifyWebAuthnWitness(w, e)
		if r.OK != c.OK {
			t.Errorf("%s: got %v %s", c.Name, r.OK, r.Reason)
		}
		checkReason(t, c, r.Reason)
		if c.ReasonPrefix != nil && !strings.HasPrefix(r.Reason, localizedReason(t, *c.ReasonPrefix)) {
			t.Errorf("%s: reason %q lacks prefix %q", c.Name, r.Reason, localizedReason(t, *c.ReasonPrefix))
		}
	}
}
