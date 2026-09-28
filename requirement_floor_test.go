package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// DIV §5 step 3d. The signed requirement is authored by the signers, so one approver who is also the
// requester can self-compose a 1-of-1 receipt for a 3-of-3 four-eyes action. Without a floor it
// verifies (legacy behaviour, pinned); with the relying party's floor it is refused on every entry
// point that counts a quorum.

type floorSigner struct {
	key  *ecdsa.PrivateKey
	spki string
}

func newFloorSigner(t *testing.T) floorSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return floorSigner{k, base64.StdEncoding.EncodeToString(der)}
}

func floorFixture(t *testing.T) (map[string]floorSigner, ApproverTrustAnchor, RequesterIdentity) {
	people := map[string]floorSigner{
		"did:ex:alice": newFloorSigner(t),
		"did:ex:bob":   newFloorSigner(t),
		"did:ex:carol": newFloorSigner(t),
	}
	anchor := ApproverTrustAnchor{
		DIDs:        []string{"did:ex:alice", "did:ex:bob", "did:ex:carol"},
		ResolveKeys: func(did string) []string { return []string{people[did].spki} },
	}
	return people, anchor, RequesterIdentity{DID: "did:ex:alice"}
}

func signFloorReceipt(t *testing.T, people map[string]floorSigner, canonical, display string, params map[string]interface{}, requester RequesterIdentity, signers ...string) ApprovalReceipt {
	t.Helper()
	es := "ES256"
	r := ApprovalReceipt{CanonicalPayload: canonical, ActionDescription: display, Params: params, Requester: &requester}
	for _, did := range signers {
		h := sha256.Sum256([]byte(canonical))
		sig, err := ecdsa.SignASN1(rand.Reader, people[did].key, h[:])
		if err != nil {
			t.Fatal(err)
		}
		r.Signatures = append(r.Signatures, ApprovalWitness{SignerDID: did, SignerPublicKey: people[did].spki, Signature: base64.StdEncoding.EncodeToString(sig), SigAlg: &es})
	}
	return r
}

func TestRequirementFloorRefusesSelfComposedDowngrade(t *testing.T) {
	people, anchor, requester := floorFixture(t)
	params := map[string]interface{}{"amount": 1000000, "to": "acct-9"}
	weak := ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human"}
	canonical, err := CanonicalIntentPayload("prod-payments", "payments.wire", "Wire", params, requester, weak, "c_real_nonce", "2999-01-01T00:00:00.000Z")
	if err != nil {
		t.Fatal(err)
	}
	receipt := signFloorReceipt(t, people, canonical, "Wire", params, requester, "did:ex:alice")
	expected := Expected{Target: "prod-payments", Nonce: "c_real_nonce", ActionType: "payments.wire", Params: params, Approvers: anchor}

	if r := VerifyApprovalReceipt(receipt, expected, VerifyOptions{}); !r.OK {
		t.Fatalf("without a floor the signers' own quorum is what is proved (legacy behaviour): %s", r.Reason)
	}
	expected.Requirement = &RequirementFloor{RequiredApprovals: 3, RequesterCannotApprove: true}
	r := VerifyApprovalReceipt(receipt, expected, VerifyOptions{})
	if r.OK || !strings.Contains(r.Reason, WeakerRequirementReason) {
		t.Fatalf("3-of-3 four-eyes floor must refuse a self-composed 1-of-1: ok=%v %s", r.OK, r.Reason)
	}
	for name, floor := range map[string]*RequirementFloor{
		"four-eyes": {RequiredApprovals: 1, RequesterCannotApprove: true},
		"hardware":  {RequiredApprovals: 1, RequireHardwareKey: true},
		"malformed": {RequiredApprovals: 0},
	} {
		expected.Requirement = floor
		if r := VerifyApprovalReceipt(receipt, expected, VerifyOptions{}); r.OK {
			t.Fatalf("%s floor accepted a weaker signed requirement", name)
		}
	}
	expected.Requirement = &RequirementFloor{RequiredApprovals: 1}
	if r := VerifyApprovalReceipt(receipt, expected, VerifyOptions{}); !r.OK {
		t.Fatalf("an equal floor must pass: %s", r.Reason)
	}
}

func TestRequirementFloorAppliesToDelegationAndAuthority(t *testing.T) {
	people, anchor, requester := floorFixture(t)
	params := map[string]interface{}{"service": "api"}
	weak := ApprovalRequirement{RequiredApprovals: 1, SignerClass: "human"}
	now := time.Now().UTC()
	sealed, exp := now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339)

	canonical, err := CanonicalDelegationPayload("prod", "restart", "Restart", params, requester, weak, []string{"did:ex:bob"}, 1, "d_nonce", sealed, exp)
	if err != nil {
		t.Fatal(err)
	}
	seal := signFloorReceipt(t, people, canonical, "Restart", params, requester, "did:ex:alice")
	expected := Expected{Target: "prod", ActionType: "restart", Params: params, Approvers: anchor}
	if r, _ := VerifyDelegation(seal, expected, VerifyOptions{}); !r.OK {
		t.Fatalf("delegation without a floor: %s", r.Reason)
	}
	expected.Requirement = &RequirementFloor{RequiredApprovals: 2}
	if r, _ := VerifyDelegation(seal, expected, VerifyOptions{}); r.OK || !strings.Contains(r.Reason, WeakerRequirementReason) {
		t.Fatalf("delegation floor not enforced: ok=%v %s", r.OK, r.Reason)
	}

	canonical, err = CanonicalAgentAuthorityPayload("prod", []string{"restart"}, "Restart", "did:ex:agent", requester, weak, "a_nonce", sealed, exp)
	if err != nil {
		t.Fatal(err)
	}
	authority := signFloorReceipt(t, people, canonical, "Restart", nil, requester, "did:ex:alice")
	ax := AgentAuthorityExpectation{Approvers: anchor, Target: "prod", AgentDID: "did:ex:agent"}
	if r, _ := VerifyAgentAuthority(authority, ax, VerifyOptions{}); !r.OK {
		t.Fatalf("authority without a floor: %s", r.Reason)
	}
	ax.Requirement = &RequirementFloor{RequiredApprovals: 2}
	if r, _ := VerifyAgentAuthority(authority, ax, VerifyOptions{}); r.OK || !strings.Contains(r.Reason, WeakerRequirementReason) {
		t.Fatalf("authority floor not enforced: ok=%v %s", r.OK, r.Reason)
	}
}
