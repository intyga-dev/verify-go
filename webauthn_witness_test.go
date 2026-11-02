package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

// VerifyWebAuthnWitness against the shared golden assertion (webauthn-vector.json), mirroring the
// reference's verifyWebAuthnWitness tests in packages/verify/src/webauthn-vector.test.ts.

func witnessOf(v webauthnVector) WebAuthnWitness {
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return WebAuthnWitness{
		SignedPayload:     v.Receipt.CanonicalPayload,
		PublicKey:         str(v.Receipt.SignerPublicKey),
		AuthenticatorData: str(v.Receipt.AuthenticatorData),
		ClientDataJSON:    str(v.Receipt.ClientDataJSON),
		Signature:         str(v.Receipt.Signature),
	}
}

func TestVerifyWebAuthnWitnessGoldenVerifiesUnderCoseOrSPKI(t *testing.T) {
	v := loadWebAuthnVector(t)
	exp := WebAuthnWitnessExpectation{ExpectedOrigin: []string{v.Origin}, ExpectedRpID: v.RpID}
	if r := VerifyWebAuthnWitness(witnessOf(v), exp); !r.OK {
		t.Fatalf("golden assertion refused: %s", r.Reason)
	}
	cose, err := decodeBase64Flexible(witnessOf(v).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(cose[10:42]), Y: new(big.Int).SetBytes(cose[45:77])}
	der, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		t.Fatal(err)
	}
	w := witnessOf(v)
	w.PublicKey = base64.StdEncoding.EncodeToString(der)
	if r := VerifyWebAuthnWitness(w, exp); !r.OK {
		t.Fatalf("same key as SPKI refused: %s", r.Reason)
	}
	multi := WebAuthnWitnessExpectation{ExpectedOrigin: []string{"https://other.example", v.Origin}, ExpectedRpID: v.RpID}
	if r := VerifyWebAuthnWitness(witnessOf(v), multi); !r.OK {
		t.Fatalf("multi-origin expectation refused: %s", r.Reason)
	}
}

func TestVerifyWebAuthnWitnessBindsPayloadKeyOriginRPAndSignature(t *testing.T) {
	v := loadWebAuthnVector(t)
	exp := WebAuthnWitnessExpectation{ExpectedOrigin: []string{v.Origin}, ExpectedRpID: v.RpID}
	refused := func(w WebAuthnWitness, e WebAuthnWitnessExpectation, want string) {
		t.Helper()
		r := VerifyWebAuthnWitness(w, e)
		if r.OK || !strings.Contains(r.Reason, want) {
			t.Errorf("want refusal containing %q, got ok=%v %q", want, r.OK, r.Reason)
		}
	}
	w := witnessOf(v)
	w.SignedPayload += " "
	refused(w, exp, "challenge does not match")

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	w = witnessOf(v)
	w.PublicKey = base64.StdEncoding.EncodeToString(otherDER)
	refused(w, exp, "WebAuthn signature does not verify against the trusted signer key")

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	w = witnessOf(v)
	w.PublicKey = base64.StdEncoding.EncodeToString(rsaDER)
	refused(w, exp, "WebAuthn verification failed: public key is not a P-256 key")

	refused(witnessOf(v), WebAuthnWitnessExpectation{ExpectedOrigin: []string{"https://evil.example.com"}, ExpectedRpID: v.RpID},
		"assertion origin does not match ExpectedOrigin")
	refused(witnessOf(v), WebAuthnWitnessExpectation{ExpectedOrigin: []string{v.Origin}, ExpectedRpID: "evil.example.com"},
		"authenticatorData rpIdHash does not match ExpectedRpID")

	sig, _ := decodeBase64Flexible(witnessOf(v).Signature)
	sig[len(sig)-1] ^= 0x01
	w = witnessOf(v)
	w.Signature = base64.StdEncoding.EncodeToString(sig)
	if r := VerifyWebAuthnWitness(w, exp); r.OK {
		t.Error("tampered signature accepted")
	}
}

func TestVerifyWebAuthnWitnessFailsClosedAndNeverPanics(t *testing.T) {
	v := loadWebAuthnVector(t)
	const needExpectations = "a WebAuthn witness requires ExpectedOrigin and ExpectedRpID — without them an assertion from any relying party would verify"
	for i, e := range []WebAuthnWitnessExpectation{
		{ExpectedOrigin: []string{""}, ExpectedRpID: v.RpID},
		{ExpectedOrigin: []string{}, ExpectedRpID: v.RpID},
		{ExpectedOrigin: []string{v.Origin}, ExpectedRpID: ""},
		{},
	} {
		if r := VerifyWebAuthnWitness(witnessOf(v), e); r.OK || r.Reason != needExpectations {
			t.Errorf("expectation %d: got ok=%v %q", i, r.OK, r.Reason)
		}
	}
	exp := WebAuthnWitnessExpectation{ExpectedOrigin: []string{v.Origin}, ExpectedRpID: v.RpID}
	for _, field := range []string{"signedPayload", "publicKey", "authenticatorData", "clientDataJSON", "signature"} {
		w := witnessOf(v)
		switch field {
		case "signedPayload":
			w.SignedPayload = ""
		case "publicKey":
			w.PublicKey = ""
		case "authenticatorData":
			w.AuthenticatorData = ""
		case "clientDataJSON":
			w.ClientDataJSON = ""
		case "signature":
			w.Signature = ""
		}
		if r := VerifyWebAuthnWitness(w, exp); r.OK || r.Reason != "WebAuthn witness missing "+field {
			t.Errorf("%s: got ok=%v %q", field, r.OK, r.Reason)
		}
	}
	w := witnessOf(v)
	w.PublicKey, w.AuthenticatorData, w.ClientDataJSON = "AAAA", "AAAA", "e30="
	if r := VerifyWebAuthnWitness(w, exp); r.OK {
		t.Error("garbage witness accepted")
	}
	// A cross-origin frame is refused unless the caller opts in.
	if r := VerifyWebAuthnWitness(witnessOf(v), WebAuthnWitnessExpectation{ExpectedOrigin: []string{v.Origin}, ExpectedRpID: v.RpID, AllowCrossOrigin: true}); !r.OK {
		t.Errorf("AllowCrossOrigin must not refuse a same-origin assertion: %s", r.Reason)
	}
}

// TestWebAuthnSignatureIsDEROnly: the golden assertion's signature re-encoded as raw r‖s (IEEE P1363)
// is refused on both the standalone and the receipt path, with the reference's text.
func TestWebAuthnSignatureIsDEROnly(t *testing.T) {
	v := loadWebAuthnVector(t)
	der, err := decodeBase64Flexible(witnessOf(v).Signature)
	if err != nil {
		t.Fatal(err)
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	rawB64 := base64.StdEncoding.EncodeToString(raw)
	const want = "WebAuthn signature does not verify against the trusted signer key"

	w := witnessOf(v)
	w.Signature = rawB64
	exp := WebAuthnWitnessExpectation{ExpectedOrigin: []string{v.Origin}, ExpectedRpID: v.RpID}
	if r := VerifyWebAuthnWitness(w, exp); r.OK || r.Reason != want {
		t.Fatalf("raw r||s witness: ok=%v %q", r.OK, r.Reason)
	}

	receipt := v.Receipt
	receipt.Signature = &rawB64
	r := VerifyApprovalReceipt(receipt, v.expected(), VerifyOptions{ExpectedOrigin: v.Origin, ExpectedRpID: v.RpID})
	if wantReceipt := "quorum not met: 0 of 1 required approver signatures verified (" + want + ")"; r.OK || r.Reason != wantReceipt {
		t.Fatalf("raw r||s receipt: ok=%v %q", r.OK, r.Reason)
	}
}
