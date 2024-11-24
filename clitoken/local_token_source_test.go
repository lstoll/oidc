package clitoken

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type captureOpener struct {
	t    *testing.T
	urlC chan string
}

func (c *captureOpener) Open(ctx context.Context, url string) error {
	c.t.Logf("open called for: %s", url)
	c.urlC <- url
	return nil
}

func TestLocalTokenSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	t.Cleanup(cancel)

	const accessToken = "youareok"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		redir := r.URL.Query().Get("redirect_uri")
		redir = redir + "?code=1234&state=" + r.URL.Query().Get("state")
		t.Logf("/auth redirect to: %s", redir)
		http.Redirect(w, r, redir, http.StatusSeeOther)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json;charset=UTF-8")
		resp := map[string]any{
			"access_token": accessToken,
			"expires_in":   60,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	// needs this to trust the self-signed cert. Also a demo of how to use a
	// custom HTTP client.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, srv.Client())

	openC := make(chan string)
	co := &captureOpener{t: t, urlC: openC}

	cfg := Config{
		OAuth2Config: oauth2.Config{
			Endpoint: oauth2.Endpoint{
				AuthURL:  srv.URL + "/auth",
				TokenURL: srv.URL + "/token",
			},
		},
		Opener: co,
	}

	ts, err := cfg.TokenSource(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var (
		tokC    = make(chan *oauth2.Token)
		tokErrC = make(chan error)
	)
	go func() {
		t, err := ts.Token()
		if err != nil {
			tokErrC <- err
			return
		}
		tokC <- t
	}()

	select {
	case acurl := <-openC:
		req, err := http.NewRequest(http.MethodGet, acurl, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("resp status: %d", resp.StatusCode)
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for open")
	}

	select {
	case err := <-tokErrC:
		t.Fatal(err)
	case tok := <-tokC:
		if tok.AccessToken != accessToken {
			t.Errorf("want access token %s, got: %#v", accessToken, tok)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for token")
	}
}
