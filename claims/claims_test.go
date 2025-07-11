package claims

import (
	"math/rand/v2"
	"reflect"

	"github.com/google/go-cmp/cmp"
)

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
