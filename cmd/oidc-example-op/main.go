package main

import (
	"log"
	"net/http"
	"time"

	"github.com/lstoll/oidc/core"
	"github.com/lstoll/oidc/discovery"
)

func main() {
	smgr := newStubSMGR()
	privh, pubh := mustInitKeyset()

	clients := staticClients([]client{
		{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURL:  "http://localhost:8084/callback",
		},
		{
			ClientID:     "cli",
			ClientSecret: "cli-client-secret",
			Public:       true,
		},
	})

	oidc, err := core.New(&core.Config{
		AuthValidityTime: 5 * time.Minute,
		CodeValidityTime: 5 * time.Minute,
	}, smgr, clients, core.StaticKeysetHandle(privh))
	if err != nil {
		log.Fatalf("Failed to create OIDC server instance: %v", err)
	}

	iss := "http://localhost:8085"

	m := http.NewServeMux()

	svr := &server{
		oidc:            oidc,
		storage:         smgr,
		tokenValidFor:   30 * time.Second,
		refreshValidFor: 5 * time.Minute,
	}

	m.Handle("/", svr)

	md := &discovery.ProviderMetadata{
		Issuer:                iss,
		AuthorizationEndpoint: iss + "/auth",
		TokenEndpoint:         iss + "/token",
		JWKSURI:               iss + "/jwks.json",
	}

	discoh, err := discovery.NewConfigurationHandler(md, discovery.WithCoreDefaults())
	if err != nil {
		log.Fatalf("Failed to initialize discovery handler: %v", err)
	}
	m.Handle("/.well-known/openid-configuration/", discoh)

	jwksh, err := discovery.NewKeysHandler(discovery.StaticPublicKeysetHandle(pubh), 1*time.Second)
	if err != nil {
		log.Fatalf("creating keys handler: %v", err)
	}
	m.Handle("/jwks.json", jwksh)

	log.Printf("Listening on: %s", "localhost:8085")
	err = http.ListenAndServe("localhost:8085", m)
	if err != nil {
		log.Fatal(err)
	}
}
