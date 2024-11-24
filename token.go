package oidc

import (
	"encoding/json"
	"errors"

	"golang.org/x/oauth2"
)

// GetIDToken extracts the ID token from the given oauth2 Token
func GetIDToken(tok *oauth2.Token) (string, bool) {
	idt, ok := tok.Extra("id_token").(string)
	return idt, ok
}

// AddIDToken reconstructs the oauth2 token, with the ID token added. This
// exists because the serialized form of the oauth2 token does not contain the
// extra/ID token info, so this safely allows a token to be stored and t
func AddIDToken(tok *oauth2.Token, idToken string) *oauth2.Token {
	return tok.WithExtra(map[string]any{
		"id_token": idToken,
	})
}

// TokenWithID is a wrapper for an oauth2 token, that allows the ID Token to
// be serialized as well if present. This is used when a token needs to be
// saved/restored.
type TokenWithID struct {
	*oauth2.Token
}

// marshaledToken is our internal state we serialize/deserialize from
type marshaledToken struct {
	*oauth2.Token
	IDToken string `json:"id_token,omitempty"`
}

func (t *TokenWithID) UnmarshalJSON(b []byte) error {
	if t == nil {
		return errors.New("UnmarshalJSON: destination pointer is nil")
	}
	var mt marshaledToken
	if err := json.Unmarshal(b, &mt); err != nil {
		return err
	}
	t.Token = mt.Token
	if mt.IDToken != "" {
		t.Token = AddIDToken(t.Token, mt.IDToken)
	}
	return nil
}

func (t TokenWithID) MarshalJSON() ([]byte, error) {
	idt, _ := GetIDToken(t.Token)
	mt := marshaledToken{
		Token:   t.Token,
		IDToken: idt,
	}

	return json.Marshal(mt)
}
