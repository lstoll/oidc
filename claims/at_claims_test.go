package claims

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func TestAccessTokenClaims_Roundtrip(t *testing.T) {
	kh, err := keyset.NewHandle(jwt.HS256Template())
	if err != nil {
		t.Fatal(err)
	}
	mac, err := jwt.NewMAC(kh)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:         ptr("issuer"),
		FixedNow:               time.Now(),
		AllowMissingExpiration: true,
		ExpectedTypeHeader:     ptr(typJWTAccessToken),
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &AccessTokenClaims{}
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
	// The random filler can put in an issuer, but we need a specific one for the
	// validator.
	want.Issuer = "issuer"
	want.Expiry = UnixTime(time.Now().Add(time.Hour).Unix())
	want.Audience = nil

	raw, err := want.ToJWT(nil)
	if err != nil {
		t.Fatalf("ToJWT() error = %v", err)
	}

	compact, err := mac.ComputeMACAndEncode(raw)
	if err != nil {
		t.Fatalf("jwt.Sign() error = %v", err)
	}

	verified, err := mac.VerifyMACAndDecode(compact, validator)
	if err != nil {
		t.Fatalf("jwt.Verify() error = %v", err)
	}

	got, err := AccessTokenClaimsFromJWT(verified)
	if err != nil {
		t.Fatalf("AccessTokenClaimsFromJWT() error = %v", err)
	}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(AccessTokenClaims{})); diff != "" {
		t.Errorf("AccessTokenClaimsFromJWT() mismatch (-want +got):\n%s", diff)
	}
}
