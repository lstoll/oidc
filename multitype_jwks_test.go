package oidc

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lstoll/oidc/internal/th"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func TestMultitypeJWKS(t *testing.T) {
	// we want to support servers that have keys of multiple types. See how tink
	// handles this/
	rsah, err := keyset.NewHandle(jwt.RS256_2048_F4_Key_Template())
	if err != nil {
		t.Fatal(err)
	}
	rsapubh, err := rsah.Public()
	if err != nil {
		t.Fatal(err)
	}
	rsajwks, err := jwt.JWKSetFromPublicKeysetHandle(rsapubh)
	if err != nil {
		t.Fatal(err)
	}
	ech, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatal(err)
	}
	ecpubh, err := ech.Public()
	if err != nil {
		t.Fatal(err)
	}
	ecjwks, err := jwt.JWKSetFromPublicKeysetHandle(ecpubh)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("rsa jwks: %s", string(rsajwks))
	t.Logf("ec jwks: %s", string(ecjwks))

	mergejwksm := make(map[string]any)
	if err := json.Unmarshal(rsajwks, &mergejwksm); err != nil {
		t.Fatal(err)
	}
	ecjwksm := make(map[string]any)
	if err := json.Unmarshal(ecjwks, &ecjwksm); err != nil {
		t.Fatal(err)
	}
	for _, k := range ecjwksm["keys"].([]any) {
		mergejwksm["keys"] = append(mergejwksm["keys"].([]any), k)
	}
	mergejwks, err := json.Marshal(mergejwksm)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("merged jwks: %s", string(mergejwks))

	mergeh, err := jwt.JWKSetToPublicKeysetHandle(mergejwks)
	if err != nil {
		t.Fatal(err)
	}
	mergeVerif, err := jwt.NewVerifier(mergeh)
	if err != nil {
		t.Fatal(err)
	}

	rawjwt, err := jwt.NewRawJWT(&jwt.RawJWTOptions{
		Issuer:    th.Ptr("https://test"),
		Audience:  th.Ptr("test"),
		ExpiresAt: th.Ptr(time.Now().Add(1 * time.Minute)),
	})
	if err != nil {
		t.Fatal(err)
	}

	rsasigner, err := jwt.NewSigner(rsah)
	if err != nil {
		t.Fatal(err)
	}
	ecsigner, err := jwt.NewSigner(ech)
	if err != nil {
		t.Fatal(err)
	}

	signedrsa, err := rsasigner.SignAndEncode(rawjwt)
	if err != nil {
		t.Fatal(err)
	}
	signedec, err := ecsigner.SignAndEncode(rawjwt)
	if err != nil {
		t.Fatal(err)
	}

	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:   th.Ptr("https://test"),
		ExpectedAudience: th.Ptr("test"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, signed := range []string{signedrsa, signedec} {
		if _, err := mergeVerif.VerifyAndDecode(signed, validator); err != nil {
			t.Fatal(err)
		}
	}
}
