package discovery

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// PublicKeysetHandleFunc is used to retrieve a handle to the current public tink
// keyset handle. The returned handle should not contain private key material.
// It is called whenever a keyset is required, allowing for implementations to
// rotate the keyset in use as needed.
type PublicKeysetHandleFunc func() *keyset.Handle

// StaticPublicKeysetHandle implements PublicKeysetHandleFunc, with a keyset handle
// that never changes.
func StaticPublicKeysetHandle(h *keyset.Handle) PublicKeysetHandleFunc {
	return func() *keyset.Handle { return h }
}

// KeysHandler is a http.Handler that correctly serves the "keys" endpoint from a keysource
type KeysHandler struct {
	ph       PublicKeysetHandleFunc
	cacheFor time.Duration

	currJWKS   []byte
	currJWKSMu sync.Mutex

	lastKeysUpdate time.Time
}

// NewKeysHandler returns a KeysHandler configured to serve the keys from
// KeySource. It will cache key lookups for the cacheFor duration.
func NewKeysHandler(phf PublicKeysetHandleFunc, cacheFor time.Duration) (*KeysHandler, error) {
	jwks, err := jwt.JWKSetFromPublicKeysetHandle(phf())
	if err != nil {
		return nil, fmt.Errorf("creating jwks from keyset handle: %w", err)
	}
	return &KeysHandler{
		ph:       phf,
		cacheFor: cacheFor,

		currJWKS:       jwks,
		lastKeysUpdate: time.Now(),
	}, nil
}

func (h *KeysHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.currJWKSMu.Lock()
	defer h.currJWKSMu.Unlock()

	if h.currJWKS == nil || time.Now().After(h.lastKeysUpdate) {
		publicJWKset, err := jwt.JWKSetFromPublicKeysetHandle(h.ph())
		if err != nil {
			slog.ErrorContext(req.Context(), "failed to get public key handle", "err", err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}

		h.currJWKS = publicJWKset
		h.lastKeysUpdate = time.Now()
	}

	w.Header().Set("Content-Type", "application/jwk-set+json")
	if _, err := w.Write(h.currJWKS); err != nil {
		slog.ErrorContext(req.Context(), "failed to write jwks", "err", err.Error())
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
}
