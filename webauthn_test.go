package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// webauthnVector mirrors packages/mcp-schemas/vectors/webauthn-vector.json.
type webauthnVector struct {
	RpID     string `json:"rpId"`
	Origin   string `json:"origin"`
	Expected struct {
		Nonce        string                 `json:"nonce"`
		ActionType   string                 `json:"actionType"`
		Params       map[string]interface{} `json:"params"`
		RequesterDid string                 `json:"requesterDid"`
	} `json:"expected"`
	Receipt ApprovalReceipt `json:"receipt"`
}

func loadWebAuthnVector(t *testing.T) webauthnVector {
	t.Helper()
	path := filepath.Join("vectors", "webauthn-vector.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read webauthn vector: %v", err)
	}
	var v webauthnVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse webauthn vector: %v", err)
	}
	return v
}

func (v webauthnVector) expected() Expected {
	return Expected{Nonce: v.Expected.Nonce, ActionType: v.Expected.ActionType, Params: v.Expected.Params}
}

func TestWebAuthnValidVector(t *testing.T) {
	v := loadWebAuthnVector(t)
	res := VerifyApprovalReceipt(v.Receipt, v.expected(), VerifyOptions{
		ExpectedOrigin: v.Origin,
		ExpectedRpID:   v.RpID,
	})
	if !res.OK {
		t.Fatalf("valid WebAuthn receipt should verify, got reason=%q", res.Reason)
	}
}

func TestWebAuthnRejectsWrongOrigin(t *testing.T) {
	v := loadWebAuthnVector(t)
	res := VerifyApprovalReceipt(v.Receipt, v.expected(), VerifyOptions{
		ExpectedOrigin: "https://evil.example.com",
		ExpectedRpID:   v.RpID,
	})
	if res.OK {
		t.Fatal("assertion for a different origin must not verify")
	}
}

func TestWebAuthnRejectsWrongRpID(t *testing.T) {
	v := loadWebAuthnVector(t)
	res := VerifyApprovalReceipt(v.Receipt, v.expected(), VerifyOptions{
		ExpectedOrigin: v.Origin,
		ExpectedRpID:   "evil.example.com",
	})
	if res.OK {
		t.Fatal("assertion for a different RP ID must not verify")
	}
}

func TestWebAuthnFailsClosedWithoutPinning(t *testing.T) {
	v := loadWebAuthnVector(t)
	res := VerifyApprovalReceipt(v.Receipt, v.expected(), VerifyOptions{})
	if res.OK {
		t.Fatal("WebAuthn receipt must fail closed without ExpectedOrigin/ExpectedRpID")
	}
}

func TestWebAuthnRejectsForgedSignature(t *testing.T) {
	v := loadWebAuthnVector(t)
	forged := "Zm9yZ2VkLXNpZ25hdHVyZS10b3RhbC1nYXJiYWdl"
	v.Receipt.Signature = &forged
	res := VerifyApprovalReceipt(v.Receipt, v.expected(), VerifyOptions{
		ExpectedOrigin: v.Origin,
		ExpectedRpID:   v.RpID,
	})
	if res.OK {
		t.Fatal("forged WebAuthn signature must not verify")
	}
}

func TestWebAuthnRejectsTamperedParams(t *testing.T) {
	v := loadWebAuthnVector(t)
	exp := v.expected()
	exp.Params = map[string]interface{}{"amount": float64(999999)}
	res := VerifyApprovalReceipt(v.Receipt, exp, VerifyOptions{
		ExpectedOrigin: v.Origin,
		ExpectedRpID:   v.RpID,
	})
	if res.OK {
		t.Fatal("tampered params must not verify")
	}
}
