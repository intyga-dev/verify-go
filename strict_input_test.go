package verify

import "testing"

// Cross-language verdicts live in the verifierInputHardening parity vectors; these pin the helpers.

func TestParseSignedTimeGrammar(t *testing.T) {
	for _, s := range []string{"2027-09-01T12:00:00Z", "2027-09-01T12:00:00.123456789Z", "2027-09-01T14:00:00+02:00", "2028-02-29T00:00:00-23:59"} {
		if _, err := parseSignedTime(s); err != nil {
			t.Errorf("%s refused: %v", s, err)
		}
	}
	for _, s := range []string{"2027-09-01", "2027-09-01T12:00:00", "2027-09-01t12:00:00z", "2027-02-30T12:00:00Z", "2027-09-01T12:00:00,5Z", "2027-09-01T12:00:00+24:00", "2027-09-01T12:00:00+05:60", "2027-09-01T12:00:00.1234567891Z", "2027-06-30T23:59:60Z", "+02027-09-01T12:00:00Z"} {
		if _, err := parseSignedTime(s); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestCanonicalTextProblem(t *testing.T) {
	for _, s := range []string{`{"a":"b"}`, `{"a":"é"}`, `{"a":"😀"}`, `{"a":"\\ud800"}`, "{\"a\":\"\xc3\xa9\"}"} {
		if why := canonicalTextProblem(s); why != "" {
			t.Errorf("%s refused: %s", s, why)
		}
	}
	for _, s := range []string{`{"a":"\ud800"}`, `{"a":"\udc00"}`, `{"a":"\ud800A"}`, `{"a":"\\\ud800"}`, "{\"a\":\"\xff\"}"} {
		if canonicalTextProblem(s) == "" {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestStableStringifyRefusesInvalidUTF8(t *testing.T) {
	for _, v := range []interface{}{"\xff", []string{"ok", "\xfe"}, map[string]interface{}{"\xff": 1}, map[string]interface{}{"k": "\xc3"}} {
		if _, err := StableStringify(v); err == nil {
			t.Errorf("%q canonicalized", v)
		}
	}
	if s, err := StableStringify(map[string]interface{}{"e": "\U0001F600"}); err != nil || s != "{\"e\":\"\U0001F600\"}" {
		t.Errorf("valid text changed: %q %v", s, err)
	}
}

func TestSharedKeyCountsOnce(t *testing.T) {
	counted := map[string]string{}
	if why := sharedKeyProblem(counted, "AAEC", "did:a"); why != "" {
		t.Fatal(why)
	}
	if why := sharedKeyProblem(counted, "AAEC", "did:a"); why != "" {
		t.Fatal("the same identity re-presenting its key is not a second person:", why)
	}
	if sharedKeyProblem(counted, "AAEC", "did:b") == "" {
		t.Fatal("a second DID under the same key counted")
	}
	// base64url and unpadded spellings of the same bytes are the same key.
	if sharedKeyProblem(map[string]string{"\x00\x01\x02\xfb": "did:a"}, "AAEC-w", "did:b") == "" {
		t.Fatal("a respelled key counted as a new one")
	}
}
