package verify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func tenantTestMaterial() (RequesterIdentity, ApprovalRequirement, map[string]interface{}) {
	return RequesterIdentity{DID: "did:intyga:service:test"}, ApprovalRequirement{
		RequiredApprovals: 1, AllowedAaguids: []string{}, SignerClass: "human",
	}, map[string]interface{}{"amount": "10"}
}

func TestTenantBoundCanonicalBuilders(t *testing.T) {
	requester, requirement, params := tenantTestMaterial()
	tenant := "Tenant-A"
	builders := map[string]func() (string, error){
		"ordinary": func() (string, error) {
			return CanonicalIntentPayload("target", "action", "Display", params, requester, requirement, "nonce", "2027-01-01T00:00:00.000Z", tenant)
		},
		"offline": func() (string, error) {
			return CanonicalOfflineIntentPayload("target", "action", "Display", params, requester, requirement, "nonce", "2026-10-10T00:00:00.000Z", "2026-10-10T00:15:00.000Z", tenant)
		},
		"delegation": func() (string, error) {
			return CanonicalDelegationPayload("target", "action", "Display", params, requester, requirement, []string{"did:intyga:alice"}, 1, "nonce", "2026-10-10T00:00:00.000Z", "2026-10-11T00:00:00.000Z", tenant)
		},
		"authority": func() (string, error) {
			return CanonicalAgentAuthorityPayloadWithTenant("target", []string{"action"}, "Display", "did:intyga:agent", requester, requirement, "nonce", "2026-10-10T00:00:00.000Z", "2026-10-11T00:00:00.000Z", "", tenant)
		},
		"platform": func() (string, error) {
			return CanonicalPlatformIntentPayload(strings.Repeat("a", 64), "example.com", "subject", "2026-10-10T00:00:00.000Z", "2026-10-10T00:05:00.000Z", "nonce", tenant)
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			canonical, err := build()
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]interface{}
			if err := json.Unmarshal([]byte(canonical), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["v"] != float64(DivTenantBoundVersion) || payload["tenantId"] != tenant {
				t.Fatalf("builder did not emit tenant-bound v2: %s", canonical)
			}
		})
	}
	if _, err := CanonicalIntentPayload("target", "action", "Display", params, requester, requirement, "nonce", "2027-01-01T00:00:00.000Z", ""); err == nil {
		t.Fatal("an explicitly empty tenant must be refused")
	}
}

func TestApprovalTenantBindingIsCallerPinned(t *testing.T) {
	requester, requirement, params := tenantTestMaterial()
	canonical, err := CanonicalIntentPayload("target", "action", "Display", params, requester, requirement, "nonce", "2027-01-01T00:00:00.000Z", "Tenant-A")
	if err != nil {
		t.Fatal(err)
	}
	auto := "AUTO_APPROVED"
	receipt := ApprovalReceipt{CanonicalPayload: canonical, ActionDescription: "Display", Requester: &requester, SigAlg: &auto}
	expected := Expected{TenantID: tenantIDPtr("Tenant-A"), Target: "target", ActionType: "action", Params: params, Nonce: "nonce"}
	opts := VerifyOptions{AllowAutoApproved: true, AsOf: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)}
	if got := VerifyApprovalReceipt(receipt, expected, opts); !got.OK {
		t.Fatalf("matching tenant refused: %s", got.Reason)
	}

	withoutTenant := expected
	withoutTenant.TenantID = nil
	if got := VerifyApprovalReceipt(receipt, withoutTenant, opts); got.OK || !strings.Contains(got.Reason, "expected tenant") {
		t.Fatalf("v2 without caller tenant was not refused clearly: %+v", got)
	}
	emptyTenant := expected
	emptyTenant.TenantID = tenantIDPtr("")
	if got := VerifyApprovalReceipt(receipt, emptyTenant, opts); got.OK || !strings.Contains(got.Reason, "expected tenant") {
		t.Fatalf("v2 with an explicitly empty caller tenant was not refused clearly: %+v", got)
	}
	mismatch := expected
	mismatch.TenantID = tenantIDPtr("tenant-a")
	if got := VerifyApprovalReceipt(receipt, mismatch, opts); got.OK || !strings.Contains(got.Reason, "does not match") {
		t.Fatalf("case-sensitive tenant mismatch was not refused: %+v", got)
	}

	legacyCanonical, err := CanonicalIntentPayload("target", "action", "Display", params, requester, requirement, "nonce", "2027-01-01T00:00:00.000Z")
	if err != nil {
		t.Fatal(err)
	}
	receipt.CanonicalPayload = legacyCanonical
	legacyExpected := expected
	legacyExpected.TenantID = nil
	if got := VerifyApprovalReceipt(receipt, legacyExpected, opts); !got.OK {
		t.Fatalf("legacy v1 without a tenant expectation must remain valid: %s", got.Reason)
	}
	if got := VerifyApprovalReceipt(receipt, expected, opts); got.OK || !strings.Contains(got.Reason, "not tenant-bound") {
		t.Fatalf("legacy v1 with a tenant expectation was not refused: %+v", got)
	}
	receipt.CanonicalPayload = strings.Replace(legacyCanonical, `"v":1`, `"v":2`, 1)
	if got := VerifyApprovalReceipt(receipt, expected, opts); got.OK || !strings.Contains(got.Reason, "non-empty tenantId") {
		t.Fatalf("v2 payload missing tenantId was not refused: %+v", got)
	}
}

func TestApprovalRefusesCrossTenantDelegation(t *testing.T) {
	requester, requirement, params := tenantTestMaterial()
	canonical, err := CanonicalOfflineIntentPayload("target", "action", "Display", params, requester, requirement, "nonce", "2026-10-10T00:00:00.000Z", "2026-10-10T00:15:00.000Z", "Tenant-A")
	if err != nil {
		t.Fatal(err)
	}
	receipt := ApprovalReceipt{CanonicalPayload: canonical, ActionDescription: "Display", Requester: &requester}
	delegation := &VerifiedDelegation{TenantID: "Tenant-B", RequesterDID: requester.DID, DelegatedTo: []string{"did:intyga:alice"}, DelegatedQuorum: 1, Target: "target", ActionType: "action", Params: params, ExpiresAt: "2026-10-11T00:00:00.000Z"}
	got := VerifyApprovalReceipt(receipt, Expected{TenantID: tenantIDPtr("Tenant-A"), Target: "target", ActionType: "action", Params: params, Nonce: "nonce"}, VerifyOptions{AllowOffline: true, Delegation: delegation, AsOf: time.Date(2026, 10, 10, 0, 1, 0, 0, time.UTC)})
	if got.OK || !strings.Contains(got.Reason, "different tenants") {
		t.Fatalf("cross-tenant delegation was not refused: %+v", got)
	}
}
