package oidctest

import (
	"testing"

	"github.com/lstoll/oauth2ext/internal"
	"github.com/tink-crypto/tink-go/v2/jwt"
)

type JWTAble interface {
	ToRawJWT() (*jwt.RawJWT, error)
}

func NewVerifiedJWT(t *testing.T, rawJWT *jwt.RawJWT) *jwt.VerifiedJWT {
	return internal.NewVerifiedJWT(t, rawJWT)
}

func NewVerifiedJWTFromClaims(t *testing.T, claims JWTAble) *jwt.VerifiedJWT {
	return internal.NewVerifiedJWTFromClaims(t, claims)
}
