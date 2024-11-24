package tokencache

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

var _ oauth2.TokenSource = (*staticTokenSource)(nil)

type staticTokenSource struct {
	token string
}

type memCache struct {
	cache map[string]oauth2.Token
}

var _ CredentialCache = &memCache{}

func (m *memCache) Get(issuer, key string) (*oauth2.Token, error) {
	v, ok := m.cache[issuer+key]
	if ok {
		return &v, nil
	}
	return nil, nil
}

func (m *memCache) Set(issuer, key string, token *oauth2.Token) error {
	m.cache[issuer+key] = *token
	return nil
}

func (m *memCache) Available() bool {
	return true
}

func (s *staticTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: s.token,
		Expiry:      time.Now().Add(1 * time.Minute),
	}, nil
}

func TestCacheTokenSource(t *testing.T) {
	tok := "hello"
	cfg := Config{
		Issuer:        "https://iss",
		CacheKey:      "client",
		WrappedSource: &staticTokenSource{token: tok},
		Cache:         &memCache{cache: make(map[string]oauth2.Token)},
	}

	ts, err := cfg.TokenSource(context.TODO())
	if err != nil {
		t.Fatal(err)
	}

	gotTok, err := ts.Token()
	if err != nil {
		t.Fatal(err)
	}
	if gotTok.AccessToken != tok {
		t.Fatal("unexpected token")
	}

	// will make us panic if no cache
	ts.(*cachingTokenSource).cfg.WrappedSource = nil

	gotTok, err = ts.Token()
	if err != nil {
		t.Fatal(err)
	}
	if gotTok.AccessToken != tok {
		t.Fatal("unexpected token")
	}
}
