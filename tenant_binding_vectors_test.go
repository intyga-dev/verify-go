package verify

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type tenantBindingVectors struct {
	AgentReceiptDigestCases []struct {
		Name, Expected string
		Receipt        ApprovalReceipt
	} `json:"agentReceiptDigestCases"`
	Keys []struct {
		ID      string `json:"id"`
		DID     string `json:"did"`
		SpkiB64 string `json:"spkiB64"`
		CoseB64 string `json:"coseB64"`
	} `json:"keys"`
	Cases []struct {
		Name, Verifier                               string
		ExpectedTenantID, DelegationExpectedTenantID *string
		Receipt, DelegationReceipt                   ApprovalReceipt
		Expected, DelegationExpected                 struct {
			ApproverKeyIDs                                                            []string            `json:"approverKeyIds"`
			ApproverDIDs                                                              map[string][]string `json:"approverDids"`
			Target, ActionType, Nonce, AgentDID, PayloadHash, RpID, SubjectExternalID string
			RequesterDID                                                              string                 `json:"requesterDid"`
			AgentContext                                                              map[string]interface{} `json:"agentContext"`
			Params                                                                    map[string]interface{} `json:"params"`
		}
		Chain []struct {
			Receipt  ApprovalReceipt `json:"receipt"`
			Expected struct {
				ApproverDIDs                 map[string][]string `json:"approverDids"`
				Target, ActionType, AgentDID string
				Params                       map[string]interface{} `json:"params"`
			} `json:"expected"`
			ExpectedTenantID *string `json:"expectedTenantId"`
		} `json:"chain"`
		Action  AgentDelegatedAction `json:"action"`
		Options struct {
			AsOf, ExpectedOrigin string
			AllowOffline         bool
		} `json:"options"`
		OK bool `json:"ok"`
	} `json:"cases"`
}

func TestTenantBindingVectors(t *testing.T) {
	raw, err := os.ReadFile("vectors/tenant-binding-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors tenantBindingVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	coseKeys := map[string]string{}
	for _, key := range vectors.Keys {
		keys[key.ID] = key.SpkiB64
		coseKeys[key.ID] = key.CoseB64
	}
	publicAnchor := func(ids []string) ApproverTrustAnchor {
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			out = append(out, keys[id])
		}
		return ApproverTrustAnchor{PublicKeys: out}
	}
	didAnchor := func(mapping map[string][]string) ApproverTrustAnchor {
		dids := make([]string, 0, len(mapping))
		resolved := map[string][]string{}
		for did, ids := range mapping {
			dids = append(dids, did)
			for _, id := range ids {
				resolved[did] = append(resolved[did], keys[id])
			}
		}
		return ApproverTrustAnchor{DIDs: dids, ResolveKeys: func(did string) []string { return resolved[did] }}
	}
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			asOf, _ := time.Parse(time.RFC3339Nano, c.Options.AsOf)
			opts := VerifyOptions{AsOf: asOf, AllowOffline: c.Options.AllowOffline, ExpectedOrigin: c.Options.ExpectedOrigin}
			var result VerifyResult
			switch c.Verifier {
			case "approval":
				if len(c.Chain) > 0 {
					for _, link := range c.Chain {
						opts.AgentAuthorityChain = append(opts.AgentAuthorityChain, AgentAuthorityChainLink{
							Receipt:  link.Receipt,
							Expected: AgentAuthorityExpectation{TenantID: link.ExpectedTenantID, Target: link.Expected.Target, AgentDID: link.Expected.AgentDID, Approvers: didAnchor(link.Expected.ApproverDIDs)},
						})
					}
				}
				result = VerifyApprovalReceipt(c.Receipt, Expected{TenantID: c.ExpectedTenantID, Target: c.Expected.Target, ActionType: c.Expected.ActionType, Params: c.Expected.Params, Nonce: c.Expected.Nonce, RequesterDID: c.Expected.RequesterDID, AgentContext: c.Expected.AgentContext, Approvers: publicAnchor(c.Expected.ApproverKeyIDs)}, opts)
			case "delegation":
				result, _ = VerifyDelegation(c.Receipt, Expected{TenantID: c.ExpectedTenantID, Target: c.Expected.Target, ActionType: c.Expected.ActionType, Params: c.Expected.Params, Approvers: didAnchor(c.Expected.ApproverDIDs)}, opts)
			case "authority":
				result, _ = VerifyAgentAuthority(c.Receipt, AgentAuthorityExpectation{TenantID: c.ExpectedTenantID, Target: c.Expected.Target, AgentDID: c.Expected.AgentDID, Approvers: didAnchor(c.Expected.ApproverDIDs)}, opts)
			case "platform":
				platformKeys := make([]string, 0, len(c.Expected.ApproverKeyIDs))
				for _, id := range c.Expected.ApproverKeyIDs {
					platformKeys = append(platformKeys, coseKeys[id])
				}
				result = VerifyPlatformReceipt(c.Receipt, PlatformReceiptExpectation{TenantID: c.ExpectedTenantID, PayloadHash: c.Expected.PayloadHash, RpID: c.Expected.RpID, Nonce: c.Expected.Nonce, SubjectExternalID: c.Expected.SubjectExternalID, Approvers: ApproverTrustAnchor{PublicKeys: platformKeys}}, opts)
			case "approval-with-delegation":
				_, delegation := VerifyDelegation(c.DelegationReceipt, Expected{TenantID: c.DelegationExpectedTenantID, Target: c.DelegationExpected.Target, ActionType: c.DelegationExpected.ActionType, Params: c.DelegationExpected.Params, RequesterDID: c.DelegationExpected.RequesterDID, Approvers: didAnchor(c.DelegationExpected.ApproverDIDs)}, opts)
				opts.Delegation = delegation
				result = VerifyApprovalReceipt(c.Receipt, Expected{TenantID: c.ExpectedTenantID, Target: c.Expected.Target, ActionType: c.Expected.ActionType, Params: c.Expected.Params, Nonce: c.Expected.Nonce, Approvers: publicAnchor(c.Expected.ApproverKeyIDs)}, opts)
			case "authority-chain":
				chain := make([]AgentAuthorityChainLink, 0, len(c.Chain))
				for _, link := range c.Chain {
					chain = append(chain, AgentAuthorityChainLink{Receipt: link.Receipt, Expected: AgentAuthorityExpectation{TenantID: link.ExpectedTenantID, Target: link.Expected.Target, AgentDID: link.Expected.AgentDID, Approvers: didAnchor(link.Expected.ApproverDIDs)}})
				}
				result = VerifyAgentDelegationChain(chain, c.Action, opts)
			default:
				t.Fatalf("unknown verifier %q", c.Verifier)
			}
			if result.OK != c.OK {
				t.Fatalf("ok=%v want %v: %s", result.OK, c.OK, result.Reason)
			}
		})
	}
	for _, c := range vectors.AgentReceiptDigestCases {
		t.Run(c.Name, func(t *testing.T) {
			got, err := AgentReceiptDigest(c.Receipt)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.Expected {
				t.Fatalf("digest=%s want %s", got, c.Expected)
			}
		})
	}
}
