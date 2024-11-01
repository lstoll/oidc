package oidc

import (
	"fmt"
	"net/http"
)

// HTTPError indicates a generic HTTP error occurred during an interaction. It
// exposes details about the returned response, as well as the original error
type HTTPError struct {
	Response *http.Response
	Body     []byte
	Cause    error
}

func (h *HTTPError) Error() string {
	return fmt.Sprintf("http status %s: %s", h.Response.Status, string(h.Body))
}

func (h *HTTPError) Unwrap() error {
	return h.Cause
}
