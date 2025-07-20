package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/lstoll/oidc/claims"
	"github.com/lstoll/oidc/internal/th"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/oauth2"
)

func TestProviderDiscovery(t *testing.T) {
	svr, _ := newMockDiscoveryServer(t)

	if _, err := DiscoverProvider(context.TODO(), svr.URL, &DiscoverOptions{
		HTTPClient: svr.Client(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTokenVerification(t *testing.T) {
	svr, h := newMockDiscoveryServer(t)

	provider, err := DiscoverProvider(context.TODO(), svr.URL, &DiscoverOptions{
		HTTPClient: svr.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		Name       string
		Token      *jwt.RawJWTOptions
		VerifOpts  *jwt.ValidatorOpts
		WantErrStr string
	}{
		{
			Name: "Simple valid token",
			Token: &jwt.RawJWTOptions{
				Issuer:    th.Ptr(svr.URL),
				ExpiresAt: th.Ptr(time.Now().Add(1 * time.Minute)),
			},
		},
		{
			Name: "Issuer mismatch",
			Token: &jwt.RawJWTOptions{
				Issuer:    th.Ptr("https://other"),
				ExpiresAt: th.Ptr(time.Now().Add(1 * time.Minute)),
			},
			WantErrStr: "validating issuer claim",
		},
		{
			Name: "Expired",
			Token: &jwt.RawJWTOptions{
				Issuer:    th.Ptr(svr.URL),
				ExpiresAt: th.Ptr(time.Now().Add(-1 * time.Minute)),
			},
			WantErrStr: "token has expired",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			signed := signJWTOpts(t, h, tc.Token)

			_, err := provider.VerifyToken(context.TODO(), signed, tc.VerifOpts)
			if (err != nil && tc.WantErrStr == "") || (err == nil && tc.WantErrStr != "") || (err != nil && !strings.Contains(err.Error(), tc.WantErrStr)) {
				t.Fatalf("want err containing %s, got: %v", tc.WantErrStr, err)
			}
		})
	}
}

func TestIDTokenVerification(t *testing.T) {
	svr, h := newMockDiscoveryServer(t)

	provider, err := DiscoverProvider(context.TODO(), svr.URL, &DiscoverOptions{
		HTTPClient: svr.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		Name       string
		Token      *claims.RawIDClaims
		VerifOpts  IDTokenValidationOpts
		WantErrStr string
	}{
		{
			Name: "Simple valid token",
			Token: &claims.RawIDClaims{
				Issuer:   svr.URL,
				Expiry:   claims.UnixTime(time.Now().Add(1 * time.Minute).Unix()),
				Audience: claims.StrOrSlice([]string{"hello"}),
			},
			VerifOpts: IDTokenValidationOpts{
				Audience: "hello",
			},
		},
		{
			Name: "Audience mismatch",
			Token: &claims.RawIDClaims{
				Issuer:   svr.URL,
				Expiry:   claims.UnixTime(time.Now().Add(1 * time.Minute).Unix()),
				Audience: claims.StrOrSlice([]string{"hello"}),
			},
			VerifOpts: IDTokenValidationOpts{
				Audience: "other",
			},
			WantErrStr: "validating audience claim",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			jwt, err := tc.Token.ToRawJWT()
			if err != nil {
				t.Fatal(err)
			}
			signed := signRawJWT(t, h, jwt)

			o2t := &oauth2.Token{}
			o2t = o2t.WithExtra(map[string]any{"id_token": signed})

			_, err = provider.VerifyIDToken(context.TODO(), o2t, tc.VerifOpts)
			if (err != nil && tc.WantErrStr == "") || (err == nil && tc.WantErrStr != "") || (err != nil && !strings.Contains(err.Error(), tc.WantErrStr)) {
				t.Fatalf("want err containing %s, got: %v", tc.WantErrStr, err)
			}
		})
	}
}

func TestAccessTokenVerification(t *testing.T) {
	svr, h := newMockDiscoveryServer(t)

	provider, err := DiscoverProvider(context.TODO(), svr.URL, &DiscoverOptions{
		HTTPClient: svr.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		Name       string
		Token      *claims.RawAccessTokenClaims
		VerifOpts  AccessTokenValidationOpts
		WantErrStr string
	}{
		{
			Name: "Simple valid token",
			Token: &claims.RawAccessTokenClaims{
				Issuer:   svr.URL,
				Expiry:   claims.UnixTime(time.Now().Add(1 * time.Minute).Unix()),
				Audience: claims.StrOrSlice([]string{"hello"}),
			},
			VerifOpts: AccessTokenValidationOpts{
				Audience: "hello",
			},
		},
		{
			Name: "Audience mismatch",
			Token: &claims.RawAccessTokenClaims{
				Issuer:   svr.URL,
				Expiry:   claims.UnixTime(time.Now().Add(1 * time.Minute).Unix()),
				Audience: claims.StrOrSlice([]string{"hello"}),
			},
			VerifOpts: AccessTokenValidationOpts{
				Audience: "other",
			},
			WantErrStr: "validating audience claim",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			jwt, err := tc.Token.ToRawJWT()
			if err != nil {
				t.Fatal(err)
			}

			o2t := &oauth2.Token{
				AccessToken: signRawJWT(t, h, jwt),
			}

			_, err = provider.VerifyAccessToken(context.TODO(), o2t, tc.VerifOpts)
			if (err != nil && tc.WantErrStr == "") || (err == nil && tc.WantErrStr != "") || (err != nil && !strings.Contains(err.Error(), tc.WantErrStr)) {
				t.Fatalf("want err containing %s, got: %v", tc.WantErrStr, err)
			}
		})
	}
}

func TestUserinfo(t *testing.T) {
	wantClaims := &claims.RawIDClaims{
		Subject: "test-subject",
		Extra: map[string]any{
			"foo": "bar",
		},
	}
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(wantClaims); err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(svr.Close)

	p := &Provider{
		Metadata: &ProviderMetadata{
			UserinfoEndpoint: svr.URL,
		},
		HTTPClient: svr.Client(),
	}

	_, gotClaims, err := p.Userinfo(context.TODO(), oauth2.StaticTokenSource(&oauth2.Token{}))
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(wantClaims, gotClaims, cmpopts.IgnoreUnexported(claims.RawIDClaims{})); diff != "" {
		t.Errorf("unexpected claims (-want +got):\n%s", diff)
	}
}

func TestRefetch(t *testing.T) {
	svr, _ := newMockDiscoveryServer(t)

	provider, err := DiscoverProvider(context.TODO(), svr.URL, &DiscoverOptions{
		HTTPClient: svr.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	provider.lastHandle = nil

	if _, err := provider.PublicHandle(context.TODO()); err != nil {
		t.Fatal(err)
	}
}

func TestAccessTokenHeaderRequiredVerification(t *testing.T) {
	svr, h := newMockDiscoveryServer(t)

	provider, err := DiscoverProvider(context.TODO(), svr.URL, &DiscoverOptions{
		HTTPClient: svr.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// An ID token has no required type header, so we can use it to test that an
	// access token must have one.
	idclaims := &claims.RawIDClaims{
		Issuer:   svr.URL,
		Expiry:   claims.UnixTime(time.Now().Add(1 * time.Minute).Unix()),
		Audience: claims.StrOrSlice([]string{"hello"}),
	}
	jwt, err := idclaims.ToRawJWT()
	if err != nil {
		t.Fatal(err)
	}

	o2t := &oauth2.Token{
		AccessToken: signRawJWT(t, h, jwt),
	}

	_, err = provider.VerifyAccessToken(context.TODO(), o2t, AccessTokenValidationOpts{Audience: "hello"})
	if err == nil {
		t.Fatal("verifying an id token as an access token should have failed due to header mismatch")
	}

	if _, err = provider.VerifyAccessToken(context.TODO(), o2t, AccessTokenValidationOpts{
		Audience:              "hello",
		IgnoreTokenTypeHeader: true,
	}); err != nil {
		t.Fatalf("verifying with ignored header failed: %v", err)
	}
}

func newMockDiscoveryServer(t *testing.T) (*httptest.Server, *keyset.Handle) {
	h, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatal(err)
	}
	ph, err := h.Public()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := jwt.JWKSetFromPublicKeysetHandle(ph)
	if err != nil {
		t.Fatalf("creating jwks from handle: %v", err)
	}

	svr := httptest.NewTLSServer(nil)

	mux := http.NewServeMux()

	pmd := &ProviderMetadata{
		Issuer:                           svr.URL,
		IDTokenSigningAlgValuesSupported: []string{"ES256"},
		JWKSURI:                          svr.URL + "/.well-known/jwks.json",
	}

	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(pmd); err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")

		if _, err := w.Write(jwks); err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
	})

	svr.Config.Handler = mux

	return svr, h
}

func signJWTOpts(t *testing.T, h *keyset.Handle, jwtOpts *jwt.RawJWTOptions) string {
	rawJWT, err := jwt.NewRawJWT(jwtOpts)
	if err != nil {
		t.Fatal(err)
	}

	return signRawJWT(t, h, rawJWT)
}

func signRawJWT(t *testing.T, h *keyset.Handle, raw *jwt.RawJWT) string {
	signer, err := jwt.NewSigner(h)
	if err != nil {
		t.Fatalf("failed creating signer: %v", err)
	}
	signed, err := signer.SignAndEncode(raw)
	if err != nil {
		t.Fatalf("failed signing token: %v", err)
	}
	return signed
}
