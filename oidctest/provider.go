package oidctest

import (
	"context"
	"testing"

	"github.com/lstoll/oauth2ext/oidc"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func NewProvider(t *testing.T, iss string) (*oidc.Provider, jwt.Signer) {
	_ = t.Context() // ensure we're actually running in a test

	h, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatalf("failed to create handle: %v", err)
	}

	signer, err := jwt.NewSigner(h)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	pubh, err := h.Public()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	provider := &oidc.Provider{
		Metadata:       &oidc.ProviderMetadata{Issuer: iss},
		OverrideHandle: &staticOverride{h: pubh},
	}

	return provider, signer
}

type staticOverride struct {
	h *keyset.Handle
}

func (s *staticOverride) PublicHandle(context.Context) (*keyset.Handle, error) {
	return s.h, nil
}
