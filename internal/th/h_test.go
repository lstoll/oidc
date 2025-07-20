package th

import "testing"

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

	if v := PtrOrNil(tester.ZeroS); v != nil {
		t.Error("empty val should be nil")
	}
	if v := PtrOrNil(tester.ZeroI); v != nil {
		t.Error("empty val should be nil")
	}

	if v := PtrOrNil(tester.FilledS); v == nil || *v != tester.FilledS {
		t.Error("val should not be nil, and should match original")
	}
	if v := PtrOrNil(tester.FilledI); v == nil || *v != tester.FilledI {
		t.Error("val should not be nil, and should match original")
	}
}
