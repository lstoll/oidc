package claims

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/lstoll/oidc/internal/th"
)

func TestRawIDClaims_Roundtrip(t *testing.T) {
	want := &RawIDClaims{}
	fillStructWithRandomData(want)
	// Set time fields to ensure valid tokens
	now := time.Now()
	want.Expiry = UnixTime(now.Add(24 * time.Hour).Unix()) // 24 hours in the future
	want.IssuedAt = UnixTime(now.Unix())
	want.AuthTime = UnixTime(now.Unix())
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

	got := &RawIDClaims{}
	if err := json.Unmarshal(jsonPayload, got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(RawIDClaims{}), cmp.Comparer(equalMapStringAny)); diff != "" {
		t.Errorf("ToRawJWT() mismatch (-want +got):\n%s", diff)
	}

	// Test that marshalling and unmarshalling the struct directly also works.
	jsonData, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	got2 := &RawIDClaims{}
	if err := json.Unmarshal(jsonData, got2); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if diff := cmp.Diff(want, got2, cmpopts.IgnoreUnexported(RawIDClaims{}), cmp.Comparer(equalMapStringAny)); diff != "" {
		t.Errorf("JSON Marshal/Unmarshal mismatch (-want +got):\n%s", diff)
	}
}

func TestVerifiedIDClaims(t *testing.T) {
	ric := &RawIDClaims{}
	fillStructWithRandomData(ric)
	// Set time fields to ensure valid tokens
	now := time.Now()
	ric.Expiry = UnixTime(now.Add(24 * time.Hour).Unix()) // 24 hours in the future
	ric.IssuedAt = UnixTime(now.Unix())
	ric.AuthTime = UnixTime(now.Unix())
	// The audience has a custom marshaller that will make a single entry array
	// a string, so for a round trip test we need to either make it a single
	// entry, or a multi entry array.
	ric.Audience = []string{"a"}

	verifiedJWT := th.Must(newVerifiedJWT(t, ric, nil))
	vic := &VerifiedIDClaims{VerifiedJWT: verifiedJWT}

	if !vic.HasAuthTime() {
		t.Error("HasAuthTime() = false, want true")
	}
	if got, err := vic.AuthTime(); err != nil || got.Unix() != int64(ric.AuthTime) {
		t.Errorf("AuthTime() = %v, %v, want %v", got, err, ric.AuthTime.Time())
	}

	if !vic.HasNonce() {
		t.Error("HasNonce() = false, want true")
	}
	if got, err := vic.Nonce(); err != nil || got != ric.Nonce {
		t.Errorf("Nonce() = %v, %v, want %v", got, err, ric.Nonce)
	}

	if !vic.HasACR() {
		t.Error("HasACR() = false, want true")
	}
	if got, err := vic.ACR(); err != nil || got != ric.ACR {
		t.Errorf("ACR() = %v, %v, want %v", got, err, ric.ACR)
	}

	if !vic.HasAMR() {
		t.Error("HasAMR() = false, want true")
	}
	if got, err := vic.AMR(); err != nil || !cmp.Equal(got, ric.AMR) {
		t.Errorf("AMR() = %v, %v, want %v", got, err, ric.AMR)
	}

	if !vic.HasAZP() {
		t.Error("HasAZP() = false, want true")
	}
	if got, err := vic.AZP(); err != nil || got != ric.AZP {
		t.Errorf("AZP() = %v, %v, want %v", got, err, ric.AZP)
	}
}
