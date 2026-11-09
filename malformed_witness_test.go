package verify

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Audit A-04 (6 Nov 2026): the witness array is one artifact. A null, an empty object or a
// signature-less element refuses the whole receipt with a reason — a null beside a valid witness is
// not "one non-verifying witness". TS, Java and Python agree; Rust refuses at parse. Pinned across
// ports by the tenant-v2-intent-malformed-witness-beside-valid vector.
func TestMalformedWitnessElementsAreRefused(t *testing.T) {
	raw, err := os.ReadFile("vectors/tenant-binding-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var typed tenantBindingVectors
	if err := json.Unmarshal(raw, &typed); err != nil {
		t.Fatal(err)
	}
	var untyped struct {
		Cases []struct {
			Name    string          `json:"name"`
			Receipt json.RawMessage `json:"receipt"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &untyped); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, key := range typed.Keys {
		keys[key.ID] = key.SpkiB64
	}
	find := func(name string) (map[string]interface{}, int) {
		for i, c := range untyped.Cases {
			if c.Name == name {
				var m map[string]interface{}
				if err := json.Unmarshal(c.Receipt, &m); err != nil {
					t.Fatal(err)
				}
				return m, i
			}
		}
		t.Fatalf("vector %s missing", name)
		return nil, -1
	}
	// Rebuild the receipt with `signatures` set to the given elements and no top-level witness.
	withSignatures := func(base map[string]interface{}, sigs interface{}) ApprovalReceipt {
		m := map[string]interface{}{}
		for k, v := range base {
			if k != "signerDid" && k != "signerPublicKey" && k != "signature" && k != "sigAlg" {
				m[k] = v
			}
		}
		m["signatures"] = sigs
		encoded, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var receipt ApprovalReceipt
		if err := json.Unmarshal(encoded, &receipt); err != nil {
			t.Fatalf("%s: %v", encoded, err)
		}
		return receipt
	}
	witnessOf := func(base map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{
			"signerDid": base["signerDid"], "signerPublicKey": base["signerPublicKey"],
			"signature": base["signature"], "sigAlg": base["sigAlg"],
		}
	}

	intent, i := find("tenant-v2-intent-valid")
	c := typed.Cases[i]
	asOf, _ := time.Parse(time.RFC3339Nano, c.Options.AsOf)
	opts := VerifyOptions{AsOf: asOf}
	anchor := ApproverTrustAnchor{PublicKeys: []string{keys[c.Expected.ApproverKeyIDs[0]]}}
	expected := Expected{TenantID: c.ExpectedTenantID, Target: c.Expected.Target, ActionType: c.Expected.ActionType, Params: c.Expected.Params, Nonce: c.Expected.Nonce, Approvers: anchor}
	valid := witnessOf(intent)

	if r := VerifyApprovalReceipt(withSignatures(intent, []interface{}{valid}), expected, opts); !r.OK {
		t.Fatalf("control: the fixture's own witness must verify: %s", r.Reason)
	}
	for name, sigs := range map[string]interface{}{
		"[null]":            []interface{}{nil},
		"[{}]":              []interface{}{map[string]interface{}{}},
		"[valid, null]":     []interface{}{valid, nil},
		"[empty signature]": []interface{}{map[string]interface{}{"signerDid": valid["signerDid"], "signerPublicKey": valid["signerPublicKey"], "signature": "", "sigAlg": "ES256"}},
	} {
		r := VerifyApprovalReceipt(withSignatures(intent, sigs), expected, opts)
		if r.OK || !strings.Contains(r.Reason, "malformed witness") {
			t.Errorf("%s: ok=%v reason=%q", name, r.OK, r.Reason)
		}
	}

	// The same guard sits in front of the authority verifier (and delegation and platform).
	authority, j := find("tenant-v2-authority-valid")
	a := typed.Cases[j]
	resolved := map[string][]string{}
	dids := []string{}
	for did, ids := range a.Expected.ApproverDIDs {
		dids = append(dids, did)
		for _, id := range ids {
			resolved[did] = append(resolved[did], keys[id])
		}
	}
	authorityExpected := AgentAuthorityExpectation{TenantID: a.ExpectedTenantID, Target: a.Expected.Target, AgentDID: a.Expected.AgentDID, Approvers: ApproverTrustAnchor{DIDs: dids, ResolveKeys: func(did string) []string { return resolved[did] }}}
	authorityAsOf, _ := time.Parse(time.RFC3339Nano, a.Options.AsOf)
	if r, _ := VerifyAgentAuthority(withSignatures(authority, []interface{}{witnessOf(authority)}), authorityExpected, VerifyOptions{AsOf: authorityAsOf}); !r.OK {
		t.Fatalf("authority control: %s", r.Reason)
	}
	if r, _ := VerifyAgentAuthority(withSignatures(authority, []interface{}{witnessOf(authority), nil}), authorityExpected, VerifyOptions{AsOf: authorityAsOf}); r.OK || !strings.HasPrefix(r.Reason, "authority carries a malformed witness") {
		t.Errorf("authority [valid, null]: ok=%v reason=%q", r.OK, r.Reason)
	}
}
