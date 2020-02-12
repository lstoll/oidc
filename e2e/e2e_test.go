package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/pardot/oidc"
	"github.com/pardot/oidc/core"
	"github.com/pardot/oidc/discovery"
	"github.com/pardot/oidc/signer"
	"gopkg.in/square/go-jose.v2"
)

func TestE2E(t *testing.T) {
	const (
		clientID     = "client-id"
		clientSecret = "client-secret"
	)

	for _, tc := range []struct {
		Name string
	}{
		{
			Name: "Simple authorization",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			callbackChan := make(chan string, 1)
			state := randomStateValue()

			cliSvr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if errMsg := req.FormValue("error"); errMsg != "" {
					t.Errorf("error returned to callback %s: %s", errMsg, req.FormValue("error_description"))

					w.WriteHeader(http.StatusBadRequest)
					return
				}

				code := req.FormValue("code")
				if code == "" {
					t.Error("no code in callback response")

					w.WriteHeader(http.StatusBadRequest)
					return
				}

				gotState := req.FormValue("state")
				if gotState == "" || gotState != state {
					t.Errorf("returned state doesn't match request state")

					w.WriteHeader(http.StatusBadRequest)
					return
				}

				callbackChan <- code
			}))
			defer cliSvr.Close()

			cfg := &core.Config{
				AuthValidityTime: 1 * time.Minute,
				CodeValidityTime: 1 * time.Minute,
			}
			smgr := newStubSMGR()
			clientSource := &stubCS{
				ValidClients: map[string]csClient{
					clientID: csClient{
						Secret:      clientSecret,
						RedirectURI: cliSvr.URL,
					},
				},
			}

			oidcHandlers, err := core.New(cfg, smgr, clientSource, testSigner)
			if err != nil {
				t.Fatal(err)
			}

			mux := http.NewServeMux()
			oidcSvr := httptest.NewServer(mux)
			defer oidcSvr.Close()

			mux.HandleFunc("/authorization", func(w http.ResponseWriter, req *http.Request) {
				ar, err := oidcHandlers.StartAuthorization(w, req)
				if err != nil {
					t.Fatalf("error starting authorization flow: %v", err)
				}

				// just finish it straight away
				if err := oidcHandlers.FinishAuthorization(w, req, ar.SessionID, &core.Authorization{Scopes: []string{"openid"}}); err != nil {
					t.Fatalf("error finishing authorization: %v", err)
				}
			})

			mux.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
				err := oidcHandlers.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
					return &core.TokenResponse{
						IDToken:               tr.PrefillIDToken(oidcSvr.URL, "test-sub", time.Now().Add(1*time.Minute)),
						AccessTokenValidUntil: time.Now().Add(1 * time.Minute),
					}, nil
				})
				if err != nil {
					t.Errorf("error in token endpoint: %v", err)
				}
			})

			// discovery endpoint
			md := &discovery.ProviderMetadata{
				Issuer:                oidcSvr.URL,
				AuthorizationEndpoint: oidcSvr.URL + "/authorization",
				TokenEndpoint:         oidcSvr.URL + "/token",
				JWKSURI:               oidcSvr.URL + "/jwks.json",
			}

			discoh, err := discovery.NewConfigurationHandler(md, discovery.WithCoreDefaults())
			if err != nil {
				log.Fatalf("Failed to initialize discovery handler: %v", err)
			}
			mux.Handle("/.well-known/openid-configuration/", discoh)

			jwksh := discovery.NewKeysHandler(testSigner, 1*time.Second)
			mux.Handle("/jwks.json", jwksh)

			// set up client
			cl, err := oidc.DiscoverClient(ctx, oidcSvr.URL, clientID, clientSecret, cliSvr.URL)
			if err != nil {
				t.Fatalf("discovering client: %v", err)
			}

			client := &http.Client{}
			resp, err := client.Get(cl.AuthCodeURL(state))
			if err != nil {
				t.Fatalf("error getting auth URL: %v", err)
			}
			defer resp.Body.Close()

			var callbackCode string
			select {
			case callbackCode = <-callbackChan:
			case <-time.After(1 * time.Second):
				t.Fatal("waiting for callback timed out after 1s")
			}

			tok, err := cl.Exchange(ctx, callbackCode)
			if err != nil {
				t.Fatalf("error exchanging code %q for token: %v", callbackCode, err)
			}

			t.Logf("claims: %#v", tok.Claims)
		})
	}
}

func randomStateValue() string {
	const numBytes = 16

	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return base64.RawStdEncoding.EncodeToString(b)
}

// contains helpers used by multiple tests

type csClient struct {
	Secret      string
	RedirectURI string
}

type stubCS struct {
	ValidClients map[string]csClient
}

func (s *stubCS) IsValidClientID(clientID string) (ok bool, err error) {
	_, ok = s.ValidClients[clientID]
	return ok, nil
}

func (s *stubCS) IsUnauthenticatedClient(clientID string) (ok bool, err error) {
	return false, nil
}

func (s *stubCS) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	cl, ok := s.ValidClients[clientID]
	return ok && clientSecret == cl.Secret, nil
}

func (s *stubCS) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	cl, ok := s.ValidClients[clientID]
	return ok && redirectURI == cl.RedirectURI, nil
}

type stubSMGR struct {
	// sessions maps JSON session objects by their ID
	// JSON > proto here for better debug output
	sessions map[string]string
}

func newStubSMGR() *stubSMGR {
	return &stubSMGR{
		sessions: map[string]string{},
	}
}

func (s *stubSMGR) NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("can't create ID, rand.Read failed: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *stubSMGR) GetSession(_ context.Context, sessionID string, into core.Session) (found bool, err error) {
	sess, ok := s.sessions[sessionID]
	if !ok {
		return false, nil
	}
	if err := jsonpb.UnmarshalString(sess, into); err != nil {
		return false, err
	}
	return true, nil
}

func (s *stubSMGR) PutSession(_ context.Context, sess core.Session) error {
	if sess.GetId() == "" {
		return fmt.Errorf("session has no ID")
	}
	strsess, err := (&jsonpb.Marshaler{}).MarshalToString(sess)
	if err != nil {
		return err
	}
	s.sessions[sess.GetId()] = strsess
	return nil
}

func (s *stubSMGR) DeleteSession(ctx context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}

var testSigner = func() *signer.StaticSigner {
	key := mustGenRSAKey(512)

	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{
		Key:   key,
		KeyID: "testkey",
	}}

	verificationKeys := []jose.JSONWebKey{
		{
			Key:       key.Public(),
			KeyID:     "testkey",
			Algorithm: "RS256",
			Use:       "sig",
		},
	}

	return signer.NewStatic(signingKey, verificationKeys)
}()

func mustGenRSAKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	return key
}