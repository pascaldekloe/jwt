package jwt

import (
	"fmt"
	"testing"
	"time"
)

func TestNumericTimeMapping(t *testing.T) {
	if got := NewNumericTime(time.Time{}); got != nil {
		t.Errorf("NewNumericTime from zero value got %f, want nil", *got)
	}
	if got := (*NumericTime)(nil).Time(); !got.IsZero() {
		t.Errorf("nil NumericTime got %s, want zero value", got)
	}
	if got := (*NumericTime)(nil).String(); got != "" {
		t.Errorf("nil NumericTime String got %q", got)
	}

	n := NumericTime(1234567890.12)
	d := time.Date(2009, 2, 13, 23, 31, 30, 12E7, time.UTC)

	if got := NewNumericTime(d); got == nil {
		t.Error("NewNumericTime from non-zero value got nil")
	} else if *got != n {
		t.Errorf("NewNumericTime got %f, want %f", *got, n)
	}
	if got := n.Time(); !got.Equal(d) {
		t.Errorf("Time got %s, want %s", got, d)
	}

	iso := "2009-02-13T23:31:30.12Z"
	if got := n.String(); got != iso {
		t.Errorf("String got %q, want %q", got, iso)
	}
}

// Redundant Set entries are ignored and overridden.
func ExampleClaims_precedence() {
	offset := time.Unix(1537622794, 0)
	c := Claims{
		Registered: Registered{
			Issuer:    "a",
			Subject:   "b",
			Audience:  "c",
			Expires:   NewNumericTime(offset.Add(time.Minute)),
			NotBefore: NewNumericTime(offset.Add(time.Second)),
			Issued:    NewNumericTime(offset),
			ID:        "d",
		},
		Set: map[string]interface{}{
			"iss": "w",
			"sub": "x",
			"aud": "y",
			"exp": NewNumericTime(offset.Add(time.Millisecond)),
			"nbf": NewNumericTime(offset.Add(time.Microsecond)),
			"iat": NewNumericTime(offset.Add(time.Nanosecond)),
			"jti": "z",
		},
	}

	// typed lookups by name
	for _, name := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"} {
		if s, ok := c.String(name); ok {
			fmt.Printf("%q: %q\n", name, s)
		}
		if n, ok := c.Number(name); ok {
			fmt.Printf("%q: %0.f\n", name, n)
		}
	}

	if err := c.Sync(); err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", c.Raw)

	// output:
	// "iss": "a"
	// "sub": "b"
	// "aud": "c"
	// "exp": 1537622854
	// "nbf": 1537622795
	// "iat": 1537622794
	// "jti": "d"
	// {"aud":"c","exp":1537622854,"iat":1537622794,"iss":"a","jti":"d","nbf":1537622795,"sub":"b"}
}

func TestClaimsValid(t *testing.T) {
	c := new(Claims)
	if !c.Valid(time.Time{}) {
		t.Error("invalidated claims without time limits for zero")
	}
	if !c.Valid(time.Now()) {
		t.Error("invalidated claims without time limits")
	}

	now := time.Now()
	c.Registered.NotBefore = NewNumericTime(now)
	c.Registered.Expires = NewNumericTime(now.Add(time.Minute))

	if c.Valid(time.Time{}) {
		t.Error("validated claims with time limits for zero time")
	}
	if c.Valid(c.Registered.NotBefore.Time().Add(-time.Second)) {
		t.Error("validated claims before time limit")
	}
	if !c.Valid(c.Registered.NotBefore.Time()) {
		t.Error("invalidated claims on time limit start")
	}
	if !c.Valid(c.Registered.NotBefore.Time().Add(time.Second)) {
		t.Error("invalidated claims within time limit")
	}
	if c.Valid(c.Registered.Expires.Time()) {
		t.Error("validated claims on time limit end")
	}
	if c.Valid(c.Registered.Expires.Time().Add(time.Second)) {
		t.Error("validated claims after time limit end")
	}
}
