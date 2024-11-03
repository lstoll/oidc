package oidc

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/oauth2"
)

/*


func TestDiscovery(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m := http.NewServeMux()
	ts := httptest.NewServer(m)

	kh, err := NewKeysHandler(PublicHandle, 1*time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	m.Handle("/jwks.json", kh)

	pm := &ProviderMetadata{
		Issuer:                ts.URL,
		JWKSURI:               ts.URL + "/jwks.json",
		AuthorizationEndpoint: "/auth",
		TokenEndpoint:         "/token",
	}

	ch, err := NewConfigurationHandler(pm, WithCoreDefaults())
	if err != nil {
		t.Fatalf("error creating handler: %v", err)
	}
	m.Handle(oidcwk, ch)

	_, err = NewClient(ctx, ts.URL)
	if err != nil {
		t.Fatalf("failed to create discovery client: %v", err)
	}
}


*/

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
				Issuer:    ptr(svr.URL),
				ExpiresAt: ptr(time.Now().Add(1 * time.Minute)),
			},
		},
		{
			Name: "Issuer mismatch",
			Token: &jwt.RawJWTOptions{
				Issuer:    ptr("https://other"),
				ExpiresAt: ptr(time.Now().Add(1 * time.Minute)),
			},
			WantErrStr: "validating issuer claim",
		},
		{
			Name: "Expired",
			Token: &jwt.RawJWTOptions{
				Issuer:    ptr(svr.URL),
				ExpiresAt: ptr(time.Now().Add(-1 * time.Minute)),
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
		Token      *IDClaims
		VerifOpts  IDTokenValidationOpts
		WantErrStr string
	}{
		{
			Name: "Simple valid token",
			Token: &IDClaims{
				Issuer:   svr.URL,
				Expiry:   UnixTime(time.Now().Add(1 * time.Minute).Unix()),
				Audience: StrOrSlice([]string{"hello"}),
			},
			VerifOpts: IDTokenValidationOpts{
				Audience: "hello",
			},
		},
		{
			Name: "Audience mismatch",
			Token: &IDClaims{
				Issuer:   svr.URL,
				Expiry:   UnixTime(time.Now().Add(1 * time.Minute).Unix()),
				Audience: StrOrSlice([]string{"hello"}),
			},
			VerifOpts: IDTokenValidationOpts{
				Audience: "other",
			},
			WantErrStr: "validating audience claim",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			jwt, err := tc.Token.ToJWT(nil)
			if err != nil {
				t.Fatal(err)
			}
			signed := signRawJWT(t, h, jwt)

			o2t := TokenWithID(&oauth2.Token{}, signed)

			_, gotc, err := provider.VerifyIDToken(context.TODO(), o2t, tc.VerifOpts)
			if (err != nil && tc.WantErrStr == "") || (err == nil && tc.WantErrStr != "") || (err != nil && !strings.Contains(err.Error(), tc.WantErrStr)) {
				t.Fatalf("want err containing %s, got: %v", tc.WantErrStr, err)
			}

			if err == nil {
				if diff := cmp.Diff(tc.Token, gotc, cmpopts.IgnoreUnexported(IDClaims{})); diff != "" {
					t.Error(diff)
				}
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
		Token      *AccessTokenClaims
		VerifOpts  AccessTokenValidationOpts
		WantErrStr string
	}{
		{
			Name: "Simple valid token",
			Token: &AccessTokenClaims{
				Issuer:   svr.URL,
				Expiry:   UnixTime(time.Now().Add(1 * time.Minute).Unix()),
				Audience: StrOrSlice([]string{"hello"}),
			},
			VerifOpts: AccessTokenValidationOpts{
				Audience: "hello",
			},
		},
		{
			Name: "Audience mismatch",
			Token: &AccessTokenClaims{
				Issuer:   svr.URL,
				Expiry:   UnixTime(time.Now().Add(1 * time.Minute).Unix()),
				Audience: StrOrSlice([]string{"hello"}),
			},
			VerifOpts: AccessTokenValidationOpts{
				Audience: "other",
			},
			WantErrStr: "validating audience claim",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			jwt, err := tc.Token.ToJWT(nil)
			if err != nil {
				t.Fatal(err)
			}

			o2t := &oauth2.Token{
				AccessToken: signRawJWT(t, h, jwt),
			}

			_, gotc, err := provider.VerifyAccessToken(context.TODO(), o2t, tc.VerifOpts)
			if (err != nil && tc.WantErrStr == "") || (err == nil && tc.WantErrStr != "") || (err != nil && !strings.Contains(err.Error(), tc.WantErrStr)) {
				t.Fatalf("want err containing %s, got: %v", tc.WantErrStr, err)
			}

			if err == nil {
				if diff := cmp.Diff(tc.Token, gotc, cmpopts.IgnoreUnexported(IDClaims{})); diff != "" {
					t.Error(diff)
				}
			}
		})
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

	idclaims := &IDClaims{
		Issuer:   svr.URL,
		Expiry:   UnixTime(time.Now().Add(1 * time.Minute).Unix()),
		Audience: StrOrSlice([]string{"hello"}),
	}
	jwt, err := idclaims.ToJWT(nil)
	if err != nil {
		t.Fatal(err)
	}

	o2t := &oauth2.Token{
		AccessToken: signRawJWT(t, h, jwt),
	}

	_, _, err = provider.VerifyAccessToken(context.TODO(), o2t, AccessTokenValidationOpts{IgnoreAudience: true})
	if err == nil {
		t.Fatal("verifying an id token as an access token should have failed due to header mismatch")
	}
}

func newMockDiscoveryServer(t *testing.T) (*httptest.Server, *keyset.Handle) {
	h, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("ks: %#v", err)
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
		t.Fatal(err)
	}

	token, err := signer.SignAndEncode(raw)
	if err != nil {
		t.Fatal(err)
	}

	return token
}
