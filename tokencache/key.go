package tokencache

import (
	"slices"
	"strings"
)

// IDTokenCacheKey represents the parameters that identify an ID token uniquely
// from other combinations.
type IDTokenCacheKey struct {
	ClientID  string
	Scopes    []string
	ACRValues []string
}

// Key builds the cache key that can be passed to a CredentialCache
func (i IDTokenCacheKey) Key() string {
	k := i.ClientID
	if len(i.Scopes) > 0 {
		k = k + ";" + strings.Join(copyAndSortStringSlice(i.Scopes), ",")
	}
	if len(i.ACRValues) > 0 {
		k = k + ";" + strings.Join(copyAndSortStringSlice(i.ACRValues), ",")
	}
	return k
}

// copyAndSortStringSlice returns a sorted list of strings without modifying
// the original slice
func copyAndSortStringSlice(s []string) []string {
	sc := make([]string, 0, len(s))
	sc = append(sc, s...)

	slices.Sort(sc)
	return sc
}
