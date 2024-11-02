package internal

import (
	"crypto/rand"
	"encoding/base32"
)

// RandText generates a secure string.
//
// Replace with https://github.com/golang/go/issues/67057
func RandText() string {
	var buf = make([]byte, 128/8)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
}
