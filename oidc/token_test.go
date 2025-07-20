package oidc

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/oauth2"
)

func TestMarshaledToken(t *testing.T) {
	in := &oauth2.Token{
		AccessToken:  "aaaaa",
		RefreshToken: "bbbbbb",
		Expiry:       time.Now(),
	}
	in = in.WithExtra(map[string]any{"id_token": "cccccc"})

	mt := &TokenWithID{in}

	b, err := json.Marshal(mt)
	if err != nil {
		t.Fatal(err)
	}

	got := new(TokenWithID)
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(in, got.Token, cmpopts.IgnoreUnexported(oauth2.Token{})); diff != "" {
		t.Error(diff)
	}

	idt, ok := GetIDToken(got.Token)
	if !ok || idt != "cccccc" {
		t.Errorf("want idt to exist and be cccccc, got: %s (exist %t)", idt, ok)
	}
}
