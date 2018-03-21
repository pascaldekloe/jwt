// Package jwt implements JWT verification.
// See "JSON Web Token (JWT)" RFC 7519
// and "JSON Web Signature (JWS)" RFC 7515.
package jwt

import (
	"encoding/json"
	"time"
)

// Claims is claims set payload representation.
type Claims struct {
	// Raw has the JSON payload. This field is read-only.
	Raw json.RawMessage

	// Set is the claims set mapped by name.
	Set map[string]interface{}

	// Registered are the IANA registered "JSON Web Token Claims".
	Registered struct {
		// Expires is the upper limit (exclusive)
		// of the applicability period.
		Expires *NumericTime `json:"exp"`
		// NotBefore is the lower limit (inclusive)
		// of the applicability period.
		NotBefore *NumericTime `json:"nbf"`
	}
}

// Valid returns whether the claims sets may be accepted
// for processing at the given moment in time.
func (c *Claims) Valid(t time.Time) bool {
	n := NewNumericTime(t)
	if n == nil {
		// if there are time limits then can't be sure.
		return c.Registered.NotBefore == nil && c.Registered.Expires == nil
	}
	if c.Registered.Expires != nil && *c.Registered.Expires <= *n {
		return false
	}
	if c.Registered.NotBefore != nil && *c.Registered.NotBefore > *n {
		return false
	}
	return true
}

// String returns the claim when present and if the representation
// is a a JSON string.
func (c *Claims) String(name string) (value string, ok bool) {
	v, ok := c.Set[name]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return s, true
}

// NumericTime is a JSON numeric value representing the number
// of seconds from 1970-01-01T00:00:00Z UTC until the specified
// UTC date/time, ignoring leap seconds.
type NumericTime float64

// NewNumericTime returns the the corresponding
// representation with nil for the zero value.
func NewNumericTime(t time.Time) *NumericTime {
	if t.IsZero() {
		return nil
	}
	n := NumericTime(float64(t.UnixNano()) / 1E9)
	return &n
}

// Time returns the Go mapping with the zero value for nil.
func (n *NumericTime) Time() time.Time {
	if n == nil {
		return time.Time{}
	}
	return time.Unix(0, int64(float64(*n)*float64(time.Second))).UTC()
}

// String returs the ISO representation.
func (n *NumericTime) String() string {
	if n == nil {
		return ""
	}
	return n.Time().Format("2006-01-02T15:04:05.999999999Z")
}
