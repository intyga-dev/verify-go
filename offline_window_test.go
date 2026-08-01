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

// The offline path had no test in this package at all, which is how the defect below survived a
// green gate in three of the four ports.
//
// DIV §5a.3 makes the validity window the ENTIRE revocation story for an offline proof: a relying
// party verifying out of band has no channel to recall one, so MaxOfflineWindowMinutes is the only
// thing bounding it. The window check used to be written `if expiry, err := time.Parse(...);
// err == nil { ...checks... }`, so an expiresAt this port could not parse skipped the cap AND the
// negative-window sanity check. The only other place expiresAt is parsed is the expiry check, and
// that one is disabled by AllowExpired — so `AllowOffline + AllowExpired`, the documented forensic
// re-verification mode and the only mode under which an offline proof is examined at all, left the
// window completely unbounded.
//
// expiresAt is inside the signed bytes, but an offline proof is minted by whoever constructs it and
// the verifier reconstructs the payload from the receipt's OWN expiresAt, so any string round-trips.
// The effect was that a 60-minute incident credential became a permanent bearer capability.

func signedOfflineReceipt(t *testing.T, challengedAt, expiresAt string) (ApprovalReceipt, Expected, VerifyOptions) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pub := base64.StdEncoding.EncodeToString(der)

	requester := RequesterIdentity{DID: "did:intyga:service:pipeline"}
	requirement := ApprovalRequirement{RequiredApprovals: 1, AllowedAaguids: []string{}}
	params := map[string]interface{}{"environment": "prod"}

	canonical, err := CanonicalOfflineIntentPayload(
		"prod-db", "deleteDatabase", "Drop prod", params,
		requester, requirement, "off-window-test", challengedAt, expiresAt,
	)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	digest := sha256.Sum256([]byte(canonical))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// IEEE P1363: fixed-width r||s, which is what the verifier expects.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	es256 := "ES256"
	receipt := ApprovalReceipt{
		CanonicalPayload:  canonical,
		ActionDescription: "Drop prod",
		Params:            params,
		Signatures: []ApprovalWitness{{
			SignerDID:       "did:intyga:human:alice",
			SignerPublicKey: pub,
			Signature:       base64.StdEncoding.EncodeToString(sig),
			SigAlg:          &es256,
		}},
		Requester: &requester,
	}
	expected := Expected{
		Target:     "prod-db",
		Nonce:      "off-window-test",
		ActionType: "deleteDatabase",
		Params:     params,
		Approvers:  ApproverTrustAnchor{PublicKeys: []string{pub}},
	}
	// The combination under which an offline proof is actually examined.
	opts := VerifyOptions{AllowOffline: true, AllowExpired: true}
	return receipt, expected, opts
}

func TestOfflineWindowRefusesUnparseableExpiry(t *testing.T) {
	// Each of these is ~10 years past challengedAt, against a 60-minute cap. Every one previously
	// returned OK=true because time.Parse rejected it and the whole block was skipped.
	for _, expiresAt := range []string{
		"2036-01-01 00:00:00Z",    // space instead of T
		"9999-99-99T99:99:99Z",    // structurally invalid
		"+002036-01-01T00:00:00Z", // ES5 extended-year form
		"2036-01-01T00:00:00",     // no zone designator
		"garbage",
	} {
		receipt, expected, opts := signedOfflineReceipt(t, "2026-01-01T00:00:00Z", expiresAt)
		got := VerifyApprovalReceipt(receipt, expected, opts)
		if got.OK {
			t.Errorf("expiresAt %q: accepted a ~10-year offline window against a %d-minute cap",
				expiresAt, MaxOfflineWindowMinutes)
			continue
		}
		if !strings.Contains(got.Reason, "expiresAt is not a valid RFC3339 timestamp") {
			t.Errorf("expiresAt %q: refused for the wrong reason: %s", expiresAt, got.Reason)
		}
	}
}

func TestOfflineWindowRefusesAnOverlongButParseableWindow(t *testing.T) {
	// The cap itself, on a timestamp that parses fine — so this fails for the window, not the parse.
	receipt, expected, opts := signedOfflineReceipt(t, "2026-01-01T00:00:00Z", "2036-01-01T00:00:00Z")
	got := VerifyApprovalReceipt(receipt, expected, opts)
	if got.OK {
		t.Fatal("accepted a 10-year offline window")
	}
	if !strings.Contains(got.Reason, "over the") {
		t.Errorf("refused for the wrong reason: %s", got.Reason)
	}
}

func TestOfflineWindowAcceptsAProofInsideTheCap(t *testing.T) {
	// The fix must not turn every offline proof into a refusal. A 30-minute window, and an offset
	// form rather than Z, since time.RFC3339 accepts both and the TS reference does too.
	challenged := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	expires := time.Now().UTC().Add(25 * time.Minute).Format("2006-01-02T15:04:05+00:00")
	receipt, expected, opts := signedOfflineReceipt(t, challenged, expires)
	got := VerifyApprovalReceipt(receipt, expected, opts)
	if !got.OK {
		t.Fatalf("refused a well-formed 30-minute offline proof: %s", got.Reason)
	}
}
