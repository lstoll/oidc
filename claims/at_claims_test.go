package claims

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestRawAccessTokenClaims_Roundtrip(t *testing.T) {
	want := &RawAccessTokenClaims{}
	fillStructWithRandomData(want, nil)
	want.Extra = map[string]any{
		"a": "b",
		"c": float64(1), // numbers are unmarshalled as float64
		"d": true,
		"e": []any{"f", "g"},
		"f": map[string]any{
			"g": "h",
		},
	}
	// The audience has a custom marshaller that will make a single entry array
	// a string, so for a round trip test we need to either make it a single
	// entry, or a multi entry array.
	want.Audience = []string{"a"}

	// Test that ToRawJWT preserves all the claims.
	rawJWT, err := want.ToRawJWT(nil)
	if err != nil {
		t.Fatalf("ToRawJWT() error = %v", err)
	}
	jsonPayload, err := rawJWT.JSONPayload()
	if err != nil {
		t.Fatalf("rawJWT.JSONPayload() error = %v", err)
	}

	got := &RawAccessTokenClaims{}
	if err := json.Unmarshal(jsonPayload, got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(RawAccessTokenClaims{})); diff != "" {
		t.Errorf("ToRawJWT() mismatch (-want +got):\n%s", diff)
	}

	// Test that marshalling and unmarshalling the struct directly also works.
	jsonData, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	got2 := &RawAccessTokenClaims{}
	if err := json.Unmarshal(jsonData, got2); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if diff := cmp.Diff(want, got2, cmpopts.IgnoreUnexported(RawAccessTokenClaims{})); diff != "" {
		t.Errorf("JSON Marshal/Unmarshal mismatch (-want +got):\n%s", diff)
	}
}
