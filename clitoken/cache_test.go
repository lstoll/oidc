package clitoken

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/lstoll/oidc/tokencache"
	"golang.org/x/oauth2"
)

func TestEncryptedFileCredentialCache(t *testing.T) {
	dir, err := os.MkdirTemp("", "cachetest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	cache := &EncryptedFileCredentialCache{
		Dir: dir,
		PassphrasePromptFunc: func(prompt string) (passphrase string, err error) {
			return "passphrase", nil
		},
	}

	testCache(t, cache)
}

func TestMemoryWriteThroughCredentialCache(t *testing.T) {
	cache := &MemoryWriteThroughCredentialCache{
		CredentialCache: &NullCredentialCache{},
	}

	testCache(t, cache)
}

func testCache(t *testing.T, cache tokencache.CredentialCache) {
	for _, tc := range []struct {
		name string
		run  func(cache tokencache.CredentialCache) (*oauth2.Token, error)
		want *oauth2.Token
	}{
		{
			name: "happy path",
			run: func(cache tokencache.CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]any{"id_token": "zyx987"})

				if err := cache.Set("https://issuer1.test", "clientID", token); err != nil {
					return nil, err
				}

				return cache.Get("https://issuer1.test", "clientID")
			},
			want: (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]any{"id_token": "zyx987"}),
		},
		{
			name: "cache miss by issuer",
			run: func(cache tokencache.CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]any{"id_token": "zyx987"})

				if err := cache.Set("https://issuer2.test", "clientID", token); err != nil {
					return nil, err
				}

				return cache.Get("https://issuer3.test", "clientID")
			},
			want: nil,
		},
		{
			name: "cache miss by key",
			run: func(cache tokencache.CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]any{"id_token": "zyx987"})

				if err := cache.Set("https://issuer4.test", "clientID1", token); err != nil {
					return nil, err
				}

				return cache.Get("https://issuer4.test", "clientID2")
			},
			want: nil,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.run(cache)
			if err != nil {
				t.Fatal(err)
			}

			// ignore token internal state, it doesn't roundtrip in an
			// comparable way.
			// TODO(lstoll) better comparison?
			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreUnexported(oauth2.Token{})); diff != "" {
				t.Fatalf("want: %+v, got %+v", tc.want, got)
			}
		})
	}
}
