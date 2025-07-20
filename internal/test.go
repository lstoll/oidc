package internal

import (
	"sync"
	"testing"

	"github.com/lstoll/oauth2ext/internal/th"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

var (
	handle     *keyset.Handle
	handleOnce sync.Once
)

func initHandle(t testing.TB) {
	handleOnce.Do(func() {
		h, err := keyset.NewHandle(jwt.ES256Template())
		if err != nil {
			t.Fatalf("failed to create handle: %v", err)
		}
		handle = h
	})
}

type JWTAble interface {
	ToRawJWT() (*jwt.RawJWT, error)
}

func NewVerifiedJWT(t *testing.T, rawJWT *jwt.RawJWT) *jwt.VerifiedJWT {
	initHandle(t)

	_ = t.Context() // ensure we're actually running in a test

	signer, err := jwt.NewSigner(handle)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	signed, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("failed to sign and encode: %v", err)
	}

	pub, err := handle.Public()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	verifier, err := jwt.NewVerifier(pub)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	validatorOpts := &jwt.ValidatorOpts{}

	if rawJWT.HasTypeHeader() {
		typ, err := rawJWT.TypeHeader()
		if err != nil {
			t.Fatalf("failed to get type header: %v", err)
		}
		validatorOpts.ExpectedTypeHeader = th.Ptr(typ)
	}
	if rawJWT.HasIssuer() {
		iss, err := rawJWT.Issuer()
		if err != nil {
			t.Fatalf("failed to get issuer: %v", err)
		}
		validatorOpts.ExpectedIssuer = th.Ptr(iss)
	}
	if rawJWT.HasAudiences() {
		aud, err := rawJWT.Audiences()
		if err != nil {
			t.Fatalf("failed to get audience: %v", err)
		}
		if len(aud) > 0 {
			// just pick the first one to pass validation
			validatorOpts.ExpectedAudience = th.Ptr(aud[0])
		}
	}

	validator, err := jwt.NewValidator(validatorOpts)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	verified, err := verifier.VerifyAndDecode(signed, validator)
	if err != nil {
		t.Fatalf("failed to verify and decode: %v", err)
	}

	return verified
}

func NewVerifiedJWTFromClaims(t *testing.T, claims JWTAble) *jwt.VerifiedJWT {
	_ = t.Context() // ensure we're actually running in a test

	rawJWT, err := claims.ToRawJWT()
	if err != nil {
		t.Fatalf("failed to create raw JWT: %v", err)
	}
	return NewVerifiedJWT(t, rawJWT)
}
