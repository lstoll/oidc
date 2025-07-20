package th

func Ptr[T any](v T) *T {
	return &v
}

func PtrOrNil[T comparable](v T) *T {
	var e T
	if v == e {
		return nil
	}
	return &v
}

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
