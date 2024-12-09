//go:build darwin && !cgo

package clitoken

import (
	"os"
	"testing"
)

func TestKeychainCLICredentialCache(t *testing.T) {
	// This test requires access to macOS Keychain
	if os.Getenv("TEST_KEYCHAIN_CREDENTIAL_CACHE") == "" {
		t.Skip("TEST_KEYCHAIN_CREDENTIAL_CACHE not set")
		return
	}

	cache := &KeychainCLICredentialCache{}

	if !cache.Available() {
		t.Fatal("cache is not available")
	}

	testCache(t, cache)
}
