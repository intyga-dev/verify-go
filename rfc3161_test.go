package verify

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSharedRfc3161Vectors(t *testing.T) {
	b, err := os.ReadFile("vectors/rfc3161-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name     string
			Anchor   SignedAnchor
			Trust    Rfc3161Trust
			Expected bool
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if got := VerifyRfc3161Anchor(c.Anchor, c.Trust).OK; got != c.Expected {
				t.Fatalf("got %v, want %v", got, c.Expected)
			}
		})
	}
}

func TestRfc3161QuorumAndDivergence(t *testing.T) {
	b, err := os.ReadFile("vectors/rfc3161-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name   string
			Anchor SignedAnchor
			Trust  Rfc3161Trust
		} `json:"cases"`
	}
	if json.Unmarshal(b, &doc) != nil {
		t.Fatal("bad vectors")
	}
	valid := doc.Cases[0]
	different := doc.Cases[1]
	external := ExternalAnchorKeys{RFC3161: map[string]Rfc3161Trust{valid.Anchor.Issuer: valid.Trust}}
	policy := AnchorPolicy{RequiredAnchors: 1, TrustedIssuers: []string{valid.Anchor.Issuer}, Quorum: "N_OF_M"}
	q := VerifyAnchorQuorum([]SignedAnchor{valid.Anchor}, valid.Anchor.DailyRoot, policy, nil, nil, external)
	if !q.OK {
		t.Fatalf("quorum failed: %+v", q)
	}
	q = VerifyAnchorQuorum(nil, valid.Anchor.DailyRoot, policy, nil, []SignedAnchor{different.Anchor}, external)
	if !q.Divergence {
		t.Fatalf("divergence not detected: %+v", q)
	}
	tampered := doc.Cases[2]
	q = VerifyAnchorQuorum([]SignedAnchor{tampered.Anchor}, valid.Anchor.DailyRoot, policy, nil, nil, external)
	if !strings.Contains(q.Note, "not verified") {
		t.Fatalf("configured verification failure needs note: %+v", q)
	}
}

func TestRfc3161UnavailableExecutable(t *testing.T) {
	b, _ := os.ReadFile("vectors/rfc3161-vectors.json")
	var doc struct {
		Cases []struct {
			Anchor SignedAnchor
			Trust  Rfc3161Trust
		} `json:"cases"`
	}
	_ = json.Unmarshal(b, &doc)
	c := doc.Cases[0]
	c.Trust.OpenSSLPath = "/definitely/missing/openssl"
	if VerifyRfc3161Anchor(c.Anchor, c.Trust).OK {
		t.Fatal("missing OpenSSL must fail closed")
	}
}

func TestRfc3161RejectsNonCanonicalAnchorFields(t *testing.T) {
	b, _ := os.ReadFile("vectors/rfc3161-vectors.json")
	var doc struct {
		Cases []struct {
			Anchor SignedAnchor
			Trust  Rfc3161Trust
		} `json:"cases"`
	}
	_ = json.Unmarshal(b, &doc)
	c := doc.Cases[0]
	for name, mutate := range map[string]func(*SignedAnchor){
		"uppercase root":        func(a *SignedAnchor) { a.DailyRoot = "E" + a.DailyRoot[1:] },
		"unsupported algorithm": func(a *SignedAnchor) { a.Algorithm = "SHA256" },
	} {
		t.Run(name, func(t *testing.T) {
			a := c.Anchor
			mutate(&a)
			if VerifyRfc3161Anchor(a, c.Trust).OK {
				t.Fatal("non-canonical anchor must fail")
			}
		})
	}
	if rfc3161MaxEncodedToken != 1398104 {
		t.Fatalf("encoded limit drifted: %d", rfc3161MaxEncodedToken)
	}
}
