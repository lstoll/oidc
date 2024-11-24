package tokencache

import (
	"golang.org/x/oauth2"
)

// CredentialCache is capable of caching and retrieving OpenID Connect tokens.
// At this time, CredentialCache implementations are not required to be
// goroutine safe. Code that uses a CredentialCache should synchronize access to
// the caches if goroutine safety is needed. This can also be used for regular
// oauth2 tokens, the issuer should be a unique URL representing the
// authorization server.
type CredentialCache interface {
	// Get returns a token from cache for the given issuer, and unique key for
	// this token. The key should take in to account the unique properties for
	// this token, e.g client ID/scopes/ACRs. Cache misses are _not_ considered
	// an error, so a cache miss will be returned as `(nil, nil)`
	Get(issuer, key string) (*oauth2.Token, error)
	// Set sets a token in the cache for the given issuer and key.
	Set(issuer, key string, token *oauth2.Token) error
	// Available returns true if the credential cache is supported on this
	// platform or environment.
	Available() bool
}
