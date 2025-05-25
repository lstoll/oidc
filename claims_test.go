package oidc

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tink-crypto/tink-go/v2/jwt"
)

func TestCustomMarshaling(t *testing.T) {
	type container struct {
		UnixTime         UnixTime
		StrOrSliceSingle StrOrSlice
		StrOrSliceSlice  StrOrSlice
	}

	c := container{
		UnixTime:         UnixTime(must(time.Parse("2006-Jan-02", "2019-Nov-20")).Unix()),
		StrOrSliceSingle: StrOrSlice([]string{"a"}),
		StrOrSliceSlice:  StrOrSlice([]string{"a", "b"}),
	}

	wantJSON := `{"UnixTime":1574208000,"StrOrSliceSingle":"a","StrOrSliceSlice":["a","b"]}`

	b, err := json.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != wantJSON {
		t.Errorf("want %s, got: %s", wantJSON, string(b))
	}

	gc := container{}

	if err := json.Unmarshal([]byte(wantJSON), &gc); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(c, gc); diff != "" {
		t.Error(diff)
	}
}

func TestRawJWT(t *testing.T) {
	// DANGERZONE!! This is a quick hack for testing. Never do it outside of
	// this context. Is fragile, will need updates when tink changes their
	// internal state.
	rawToVerified := func(raw *jwt.RawJWT) *jwt.VerifiedJWT {
		verifiedJWT := &jwt.VerifiedJWT{}
		v := reflect.ValueOf(verifiedJWT).Elem()
		field := v.FieldByName("token")
		if field.CanSet() {
			field.Set(reflect.ValueOf(raw))
		} else {
			reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(raw))
		}
		return verifiedJWT
	}

	type jwtable interface {
		ToJWT(extraClaims map[string]any) (*jwt.RawJWT, error)
	}

	for _, tc := range []struct {
		Name          string
		IgnoreFields  []string
		NewFn         func() jwtable
		FromFn        func(*jwt.RawJWT) (any, error)
		WantCreateErr bool
		WantLoadErr   bool
	}{
		{
			Name: "ID Token, all filled",
			NewFn: func() jwtable {
				return new(IDClaims)
			},
			FromFn: func(raw *jwt.RawJWT) (any, error) {
				return IDClaimsFromJWT(rawToVerified(raw))
			},
		},
		{
			Name: "Access Token, all filled",
			NewFn: func() jwtable {
				return new(AccessTokenClaims)
			},
			FromFn: func(raw *jwt.RawJWT) (any, error) {
				return AccessTokenClaimsFromJWT(rawToVerified(raw))
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			idc := tc.NewFn()
			fillStructWithRandomData(idc, tc.IgnoreFields)

			raw, err := idc.ToJWT(nil)
			if (err != nil) != tc.WantCreateErr {
				t.Fatalf("want to err: %t, got: %v", tc.WantLoadErr, err)
			}

			got, err := tc.FromFn(raw)
			if (err != nil) != tc.WantLoadErr {
				t.Fatalf("want load err: %t, got: %v", tc.WantLoadErr, err)
			}

			if diff := cmp.Diff(idc, got, cmpopts.IgnoreUnexported(IDClaims{})); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestPTROrNil(t *testing.T) {
	tester := struct {
		ZeroS   string
		ZeroI   int
		FilledS string
		FilledI int
	}{
		FilledS: "hello",
		FilledI: 42,
	}

	if v := ptrOrNil(tester.ZeroS); v != nil {
		t.Error("empty val should be nil")
	}
	if v := ptrOrNil(tester.ZeroI); v != nil {
		t.Error("empty val should be nil")
	}

	if v := ptrOrNil(tester.FilledS); v == nil || *v != tester.FilledS {
		t.Error("val should not be nil, and should match original")
	}
	if v := ptrOrNil(tester.FilledI); v == nil || *v != tester.FilledI {
		t.Error("val should not be nil, and should match original")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func fillStructWithRandomData(v any, ignoreClaims []string) {
	val := reflect.ValueOf(v).Elem()
	typeOfV := val.Type()

	for i := range val.NumField() {
		field := val.Field(i)

		jsonTag := typeOfV.Field(i).Tag.Get("json")

		if slices.Contains(ignoreClaims, jsonTag) {
			continue
		}

		switch field.Kind() {
		case reflect.String:
			field.SetString(randomString(5))
		case reflect.Slice:
			if field.Type().Elem().Kind() == reflect.String {
				field.Set(reflect.ValueOf(randomStringSlice(3)))
			}
		case reflect.Int64:
			if field.Type() == reflect.TypeOf(UnixTime(0)) {
				field.Set(reflect.ValueOf(randomUnixTime()))
			}
		case reflect.Map:
			if field.Type().Key().Kind() == reflect.String && field.Type().Elem().Kind() == reflect.String {
				field.Set(reflect.ValueOf(randomStringMap(3)))
			}
		default:
			panic(fmt.Sprintf("unknown type %s", field.Type()))
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

func randomUnixTime() UnixTime {
	offset := rand.IntN(60 * 24 * 30)
	if rand.IntN(2) == 0 {
		offset = -offset // Negate for a past time
	}
	return UnixTime(time.Now().Add(time.Duration(offset) * time.Minute).Unix())
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
