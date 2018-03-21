package jwt

import (
	"testing"
	"time"
)

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
