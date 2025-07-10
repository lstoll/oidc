package claims

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"time"
)

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
			if field.Type().Key().Kind() == reflect.String && field.Type().Elem().Kind() == reflect.Interface {
				field.Set(reflect.ValueOf(map[string]any{
					randomString(4): randomString(5),
					randomString(6): rand.IntN(100),
				}))
			} else if field.Type().Key().Kind() == reflect.String && field.Type().Elem().Kind() == reflect.String {
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
