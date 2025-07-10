package claims

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
