package claims

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/lstoll/oauth2ext/internal"
)

func TestRawAccessTokenClaims_Roundtrip(t *testing.T) {
	want := &RawAccessTokenClaims{}
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
	rawJWT, err := want.ToRawJWT()
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

	if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(RawAccessTokenClaims{}), cmp.Comparer(equalMapStringAny)); diff != "" {
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
	if diff := cmp.Diff(want, got2, cmpopts.IgnoreUnexported(RawAccessTokenClaims{}), cmp.Comparer(equalMapStringAny)); diff != "" {
		t.Errorf("JSON Marshal/Unmarshal mismatch (-want +got):\n%s", diff)
	}
}

func TestVerifiedAccessToken(t *testing.T) {
	rac := &RawAccessTokenClaims{}
	fillStructWithRandomData(rac)
	// Set time fields to ensure valid tokens
	now := time.Now()
	rac.Expiry = UnixTime(now.Add(24 * time.Hour).Unix()) // 24 hours in the future
	rac.IssuedAt = UnixTime(now.Unix())
	rac.AuthTime = UnixTime(now.Unix())
	// The audience has a custom marshaller that will make a single entry array
	// a string, so for a round trip test we need to either make it a single
	// entry, or a multi entry array.
	rac.Audience = []string{"a"}

	verifiedJWT := internal.NewVerifiedJWTFromClaims(t, rac)
	vat := &VerifiedAccessToken{VerifiedJWT: verifiedJWT}

	if !vat.HasClientID() {
		t.Error("HasClientID() = false, want true")
	}
	if got, err := vat.ClientID(); err != nil || got != rac.ClientID {
		t.Errorf("ClientID() = %v, %v, want %v", got, err, rac.ClientID)
	}

	if !vat.HasAuthTime() {
		t.Error("HasAuthTime() = false, want true")
	}
	if got, err := vat.AuthTime(); err != nil || got.Unix() != int64(rac.AuthTime) {
		t.Errorf("AuthTime() = %v, %v, want %v", got, err, rac.AuthTime.Time())
	}

	if !vat.HasACR() {
		t.Error("HasACR() = false, want true")
	}
	if got, err := vat.ACR(); err != nil || got != rac.ACR {
		t.Errorf("ACR() = %v, %v, want %v", got, err, rac.ACR)
	}

	if !vat.HasAMR() {
		t.Error("HasAMR() = false, want true")
	}
	if got, err := vat.AMR(); err != nil || !cmp.Equal(got, rac.AMR) {
		t.Errorf("AMR() = %v, %v, want %v", got, err, rac.AMR)
	}

	if !vat.HasScope() {
		t.Error("HasScope() = false, want true")
	}
	if got, err := vat.Scope(); err != nil || got != rac.Scope {
		t.Errorf("Scope() = %v, %v, want %v", got, err, rac.Scope)
	}

	if !vat.HasGroups() {
		t.Error("HasGroups() = false, want true")
	}
	if got, err := vat.Groups(); err != nil || !cmp.Equal(got, rac.Groups) {
		t.Errorf("Groups() = %v, %v, want %v", got, err, rac.Groups)
	}

	if !vat.HasRoles() {
		t.Error("HasRoles() = false, want true")
	}
	if got, err := vat.Roles(); err != nil || !cmp.Equal(got, rac.Roles) {
		t.Errorf("Roles() = %v, %v, want %v", got, err, rac.Roles)
	}

	if !vat.HasEntitlements() {
		t.Error("HasEntitlements() = false, want true")
	}
	if got, err := vat.Entitlements(); err != nil || !cmp.Equal(got, rac.Entitlements) {
		t.Errorf("Entitlements() = %v, %v, want %v", got, err, rac.Entitlements)
	}
}
