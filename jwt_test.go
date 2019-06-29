package jwt

import (
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
	d := time.Date(2009, 2, 13, 23, 31, 30, 12e7, time.UTC)

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

// Copy Registered into claims set map.
func TestClaimsSync(t *testing.T) {
	offset := time.Unix(1537622794, 0)
	c := Claims{
		// cover all registered fields
		Registered: Registered{
			Issuer:    "a",
			Subject:   "b",
			Audiences: []string{"c"},
			Expires:   NewNumericTime(offset.Add(time.Minute)),
			NotBefore: NewNumericTime(offset.Add(-time.Second)),
			Issued:    NewNumericTime(offset),
			ID:        "d",
		},
		Set: make(map[string]interface{}),
	}

	if err := c.sync(); err != nil {
		t.Fatal("sync error:", err)
	}
	const want = `{"aud":"c","exp":1537622854,"iat":1537622794,"iss":"a","jti":"d","nbf":1537622793,"sub":"b"}`
	if got := string(c.Raw); got != want {
		t.Errorf("got JSON %q, want %q", got, want)
	}
	if len(c.Set) != 7 {
		t.Errorf("got %d entries in claims set, want 7", len(c.Set))
	}
}

// Merge Registered into claims set map.
func TestClaimsSyncMerge(t *testing.T) {
	c := Claims{
		Registered: Registered{
			Subject:   "kkazanova",
			Audiences: []string{"KGB", "RU"},
		},
		Set: map[string]interface{}{
			"iss": nil,
			"sub": "karcher",
			"aud": "ISIS",
		},
	}

	if s, ok := c.String("aud"); ok {
		t.Errorf("got audience string %q for 2 element array value", s)
	}

	if err := c.sync(); err != nil {
		t.Fatal("sync error:", err)
	}
	const want = `{"aud":["KGB","RU"],"iss":null,"sub":"kkazanova"}`
	if got := string(c.Raw); got != want {
		t.Errorf("got JSON %q, want %q", got, want)
	}
}

func TestClaimsSyncNone(t *testing.T) {
	var c Claims
	if err := c.sync(); err != nil {
		t.Fatal("sync error:", err)
	}
	if string(c.Raw) != "{}" {
		t.Errorf(`got JSON %q, want "{}"`, c.Raw)
	}
	if c.Set != nil {
		t.Error("claims set map not nil after sync")
	}
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
