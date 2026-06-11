package server

import "testing"

func TestParseAmountValid(t *testing.T) {
	cases := []struct {
		in    string
		micro string
		str   string
	}{
		{"0.01", "10000", "0.01"},
		{"0.1", "100000", "0.1"},
		{"1", "1000000", "1"},
		{"1.000000", "1000000", "1"},
		{"0.000001", "1", "0.000001"},
		{"0", "0", "0"},
		{"2.5", "2500000", "2.5"},
		{" 0.01 ", "10000", "0.01"}, // trimmed
	}
	for _, c := range cases {
		a, err := ParseAmount(c.in)
		if err != nil {
			t.Fatalf("ParseAmount(%q) error: %v", c.in, err)
		}
		if got := a.MicroString(); got != c.micro {
			t.Errorf("ParseAmount(%q).MicroString() = %q, want %q", c.in, got, c.micro)
		}
		if got := a.String(); got != c.str {
			t.Errorf("ParseAmount(%q).String() = %q, want %q", c.in, got, c.str)
		}
	}
}

func TestParseAmountRejectsBad(t *testing.T) {
	// Sub-micro precision, negatives, and junk must all be rejected rather than
	// silently rounded — a price the merchant cannot charge is a money bug.
	for _, in := range []string{"-0.01", "0.0000001", "abc", "", "  ", "1.2.3", "0x10", "1e3"} {
		if _, err := ParseAmount(in); err == nil {
			t.Errorf("ParseAmount(%q) = nil error, want rejection", in)
		}
	}
}

func TestAmountMaxAndCompare(t *testing.T) {
	a, _ := ParseAmount("0.01")
	b, _ := ParseAmount("0.05")
	if !b.GreaterThan(a) {
		t.Error("0.05 should be greater than 0.01")
	}
	if Max(a, b).String() != "0.05" {
		t.Errorf("Max(0.01,0.05) = %s, want 0.05", Max(a, b).String())
	}
	if Max(b, a).String() != "0.05" {
		t.Errorf("Max(0.05,0.01) = %s, want 0.05", Max(b, a).String())
	}
}

func TestZeroAmountUsable(t *testing.T) {
	var z Amount // uninitialized
	if !z.IsZero() {
		t.Error("zero Amount should be zero")
	}
	if z.IsPositive() {
		t.Error("zero Amount should not be positive")
	}
	if z.MicroString() != "0" || z.String() != "0" {
		t.Errorf("zero Amount renders %q/%q, want 0/0", z.MicroString(), z.String())
	}
}

func TestAmountFromMicrosClampsNegative(t *testing.T) {
	if got := AmountFromMicros(-5); !got.IsZero() {
		t.Errorf("AmountFromMicros(-5) = %s, want 0", got.String())
	}
}
