package verify

import (
	"encoding/json"
	"os"
	"testing"
)

func TestAuditSignatureParity(t *testing.T) {
	raw, err := os.ReadFile("vectors/audit-signature-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Name     string
			Bundle   ProofBundle
			Root     string
			Policy   *AuditSignaturePolicy
			Status   string
			Trusted  bool
			StrictOK bool `json:"strictOk"`
		}
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors.Cases {
		t.Run(v.Name, func(t *testing.T) {
			opts := BundleVerifyOptions{TrustedRoot: v.Root, SignaturePolicy: v.Policy}
			got := VerifyBundle(v.Bundle, opts)
			if !got.OK || got.Signature.Status != v.Status || got.Signature.Trusted != v.Trusted {
				t.Fatalf("%+v", got)
			}
			opts.RequireSignatures = true
			if VerifyBundle(v.Bundle, opts).OK != v.StrictOK {
				t.Fatal("strict verdict")
			}
			b := EvidenceBundle{Kind: EvidenceBundleKind, Version: "1.0", Entries: []EvidenceEntry{{Event: EvidenceEvent{Seq: "1", CreatedAt: v.Bundle.Event.CreatedAt, Type: v.Bundle.Event.Type, Outcome: v.Bundle.Event.Outcome, Canonical: v.Bundle.Event.Canonical}, Proof: v.Bundle.Proof}}, Checkpoints: []EvidenceCheckpoint{{ID: "cp", Root: v.Root, SeqStart: "1", SeqEnd: "1"}}}
			b.Tenant.ID = "test-tenant"
			eo := EvidenceVerifyOptions{TrustedRoots: []string{v.Root}, SignaturePolicy: v.Policy}
			bulk := VerifyEvidenceBundle(b, eo)
			if !bulk.OK || len(bulk.Signatures.Checks) != 1 || bulk.Signatures.Checks[0].Status != v.Status {
				t.Fatalf("bulk: %+v", bulk)
			}
			eo.RequireSignatures = true
			if VerifyEvidenceBundle(b, eo).OK != v.StrictOK {
				t.Fatal("bulk strict verdict")
			}
		})
	}
}
