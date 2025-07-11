package claims

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func fillStructWithRandomData(v any) {
	val := reflect.ValueOf(v).Elem()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)

		switch field.Kind() {
		case reflect.String:
			field.SetString(randomString(5))
		case reflect.Slice:
			if field.Type().Elem().Kind() == reflect.String {
				field.Set(reflect.ValueOf(randomStringSlice(3)))
			}
		case reflect.Map:
			if field.Type().Key().Kind() == reflect.String && field.Type().Elem().Kind() == reflect.Interface {
				field.Set(reflect.ValueOf(map[string]any{
					randomString(4): randomString(5),
					randomString(6): rand.IntN(100),
				}))
			} else if field.Type().Key().Kind() == reflect.String && field.Type().Elem().Kind() == reflect.String {
				field.Set(reflect.ValueOf(randomStringMap(3)))
			}
		}
	}
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))]
	}
	return string(b)
}

func randomStringSlice(size int) []string {
	slice := make([]string, size)
	for i := range size {
		slice[i] = randomString(3)
	}
	return slice
}

func randomStringMap(size int) map[string]string {
	m := make(map[string]string)
	for range size {
		key := randomString(5)
		value := randomString(10)
		m[key] = value
	}
	return m
}

// equalMapStringAny compares map[string]any and treats int and float64 as
// equal if their values are equal. Intended for JSON round trip tests.
func equalMapStringAny(x, y map[string]any) bool {
	if len(x) != len(y) {
		return false
	}
	for k, xv := range x {
		yv, ok := y[k]
		if !ok {
			return false
		}
		switch xvTyped := xv.(type) {
		case int:
			if yvFloat, ok := yv.(float64); ok {
				if float64(xvTyped) != yvFloat {
					return false
				}
				continue
			}
		case float64:
			if yvInt, ok := yv.(int); ok {
				if xvTyped != float64(yvInt) {
					return false
				}
				continue
			}
		}
		if !cmp.Equal(xv, yv) {
			return false
		}
	}
	return true
}

type claimer interface {
	ToRawJWT(map[string]any) (*jwt.RawJWT, error)
}

func newVerifiedJWT(t *testing.T, c claimer, extraClaims map[string]any) (*jwt.VerifiedJWT, error) {
	t.Helper()

	// Use HMAC-SHA256 instead of ES256 for faster signing
	kh, err := keyset.NewHandle(jwt.RawHS256Template())
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle: %w", err)
	}

	rawJWT, err := c.ToRawJWT(extraClaims)
	if err != nil {
		return nil, fmt.Errorf("creating raw JWT: %w", err)
	}

	// Use MAC for HMAC signing and verification
	mac, err := jwt.NewMAC(kh)
	if err != nil {
		return nil, fmt.Errorf("creating MAC: %w", err)
	}

	compact, err := mac.ComputeMACAndEncode(rawJWT)
	if err != nil {
		return nil, fmt.Errorf("signing JWT: %w", err)
	}

	// Create validator with appropriate options
	opts := &jwt.ValidatorOpts{
		ClockSkew: 5 * time.Minute,
	}

	// Set expected audience if present
	if aud, err := rawJWT.Audiences(); err == nil && len(aud) > 0 {
		opts.ExpectedAudience = &aud[0]
	}

	// Set expected issuer if present
	if rawJWT.HasIssuer() {
		if iss, err := rawJWT.Issuer(); err == nil {
			opts.ExpectedIssuer = &iss
		}
	}

	// Set expected type header if present
	if rawJWT.HasTypeHeader() {
		if th, err := rawJWT.TypeHeader(); err == nil {
			opts.ExpectedTypeHeader = &th
		}
	}

	// Allow missing expiration for testing
	if !rawJWT.HasExpiration() {
		opts.AllowMissingExpiration = true
	}

	val, err := jwt.NewValidator(opts)
	if err != nil {
		return nil, fmt.Errorf("creating validator: %w", err)
	}

	return mac.VerifyMACAndDecode(compact, val)
}
