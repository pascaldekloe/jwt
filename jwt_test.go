package jwt

import (
	"testing"
	"time"

	"github.com/pascaldekloe/goe/verify"
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

func TestOverride(t *testing.T) {
	offset := time.Now()
	c := Claims{
		// registered struct fields take precedence
		Registered: Registered{
			Issuer:    "a",
			Subject:   "b",
			Audience:  "c",
			Expires:   NewNumericTime(offset.Add(time.Second)),
			NotBefore: NewNumericTime(offset),
			Issued:    NewNumericTime(offset.Add(-time.Second)),
			ID:        "d",
		},
		// redundant mapping to be ignored
		Set: map[string]interface{}{
			"iss": "z",
			"sub": "z",
			"aud": "z",
			"exp": NewNumericTime(offset.Add(time.Hour)),
			"nbf": NewNumericTime(offset.Add(time.Hour)),
			"iat": NewNumericTime(offset.Add(time.Hour)),
			"jti": "z",
		},
	}

	want := map[string]interface{}{
		"iss": c.Issuer,
		"sub": c.Subject,
		"aud": c.Audience,
		"exp": *c.Expires,
		"nbf": *c.NotBefore,
		"iat": *c.Issued,
		"jti": c.ID,
	}

	// should pick the struct values
	got := make(map[string]interface{})
	for name := range want {
		if s, ok := c.String(name); ok {
			got[name] = s
		} else if n, ok := c.Number(name); ok {
			got[name] = NumericTime(n)
		}
	}
	verify.Values(t, "typed lookups", got, want)

	// should replace all Set entries
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	verify.Values(t, "synced set", want, c.Set)
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

func TestTypedLookups(t *testing.T) {
	c := &Claims{
		Set: map[string]interface{}{
			"s": "a",
			"n": 99.8,
		},
	}

	if got, ok := c.String("s"); !ok {
		t.Error("string lookup miss")
	} else if got != "a" {
		t.Errorf("got %q, want \"a\"", got)
	}
	if _, ok := c.String("n"); ok {
		t.Error("got number as string")
	}
	if _, ok := c.String("x"); ok {
		t.Error("got nonexisting string")
	}

	if got, ok := c.Number("n"); !ok {
		t.Error("number lookup miss")
	} else if got != 99.8 {
		t.Errorf("got %f, want 99.8", got)
	}
	if _, ok := c.Number("s"); ok {
		t.Error("got string as number")
	}
	if _, ok := c.Number("x"); ok {
		t.Error("got nonexisting number")
	}
}
