// Package jwt implements “JSON Web Token (JWT)” RFC 7519.
// Signatures only; no unsecured nor encrypted tokens.
package jwt

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// Algorithm Identification Tokens
const (
	ES256 = "ES256" // ECDSA using P-256 and SHA-256
	ES384 = "ES384" // ECDSA using P-384 and SHA-384
	ES512 = "ES512" // ECDSA using P-521 and SHA-512
	HS256 = "HS256" // HMAC using SHA-256
	HS384 = "HS384" // HMAC using SHA-384
	HS512 = "HS512" // HMAC using SHA-512
	PS256 = "PS256" // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	PS384 = "PS384" // RSASSA-PSS using SHA-384 and MGF1 with SHA-384
	PS512 = "PS512" // RSASSA-PSS using SHA-512 and MGF1 with SHA-512
	RS256 = "RS256" // RSASSA-PKCS1-v1_5 using SHA-256
	RS384 = "RS384" // RSASSA-PKCS1-v1_5 using SHA-384
	RS512 = "RS512" // RSASSA-PKCS1-v1_5 using SHA-512
)

// When adding additional entries you also need to
// import the respective packages to link the hash
// function into the binary [crypto.Hash.Available].
var (
	// ECDSAAlgs is the ECDSA hash algorithm registration.
	ECDSAAlgs = map[string]crypto.Hash{
		ES256: crypto.SHA256,
		ES384: crypto.SHA384,
		ES512: crypto.SHA512,
	}

	// HMACAlgs is the HMAC hash algorithm registration.
	HMACAlgs = map[string]crypto.Hash{
		HS256: crypto.SHA256,
		HS384: crypto.SHA384,
		HS512: crypto.SHA512,
	}

	// RSAAlgs is the RSA hash algorithm registration.
	RSAAlgs = map[string]crypto.Hash{
		PS256: crypto.SHA256,
		PS384: crypto.SHA384,
		PS512: crypto.SHA512,
		RS256: crypto.SHA256,
		RS384: crypto.SHA384,
		RS512: crypto.SHA512,
	}
)

// ErrAlgUnk signals an unsupported "alg" value (for the respective method).
var ErrAlgUnk = errors.New("jwt: algorithm unknown")

// See crypto.Hash.Available.
var errHashLink = errors.New("jwt: hash function not linked into binary")

var encoding = base64.RawURLEncoding

// Standard (IANA registered) claim names.
const (
	issuer    = "iss"
	subject   = "sub"
	audience  = "aud"
	expires   = "exp"
	notBefore = "nbf"
	issued    = "iat"
	id        = "jti"
)

// Registered are the IANA registered “JSON Web Token Claims”.
type Registered struct {
	// Issuer identifies the principal that issued the JWT.
	Issuer string `json:"iss,omitempty"`

	// Subject identifies the principal that is the subject of the JWT.
	Subject string `json:"sub,omitempty"`

	// Audiences identifies the recipients that the JWT is intended for.
	Audiences []string `json:"aud,omitempty"`

	// Expires identifies the expiration time on or after which the JWT
	// must not be accepted for processing.
	Expires *NumericTime `json:"exp,omitempty"`

	// NotBefore identifies the time before which the JWT must not be
	// accepted for processing.
	NotBefore *NumericTime `json:"nbf,omitempty"`

	// Issued identifies the time at which the JWT was issued.
	Issued *NumericTime `json:"iat,omitempty"`

	// ID provides a unique identifier for the JWT.
	ID string `json:"jti,omitempty"`
}

// Claims is JWT payload representation.
type Claims struct {
	// Registered field values take precedence.
	Registered

	// Raw has the JSON payload. This field is read-only.
	Raw json.RawMessage

	// Set has the claims set mapped by name for non-standard usecases.
	// Use Registered fields where possible. Note that JSON/JavaScript
	// numbers are always of the double precision floating-point type.
	// Non-standard claims are read as follows.
	//
	//	bool, for JSON booleans
	//	float64, for JSON numbers
	//	string, for JSON strings
	//	[]interface{}, for JSON arrays
	//	map[string]interface{}, for JSON objects
	//	nil for JSON null
	Set map[string]interface{}

	// “The "kid" (key ID) Header Parameter is a hint indicating which key
	// was used to secure the JWS.  This parameter allows originators to
	// explicitly signal a change of key to recipients.  The structure of
	// the "kid" value is unspecified.  Its value MUST be a case-sensitive
	// string.  Use of this Header Parameter is OPTIONAL.”
	// — “JSON Web Signature (JWS)” RFC 7515, subsection 4.1.4
	KeyID string
}

// Sync updates the Raw field. When the Set field is not nil,
// then all non-zero Registered values are copied into the map.
func (c *Claims) Sync() error {
	var payload interface{}

	if c.Set == nil {
		payload = &c.Registered
	} else {
		payload = c.Set

		if c.Issuer != "" {
			c.Set[issuer] = c.Issuer
		}
		if c.Subject != "" {
			c.Set[subject] = c.Subject
		}
		switch len(c.Audiences) {
		case 0:
			break
		case 1:
			c.Set[audience] = c.Audiences[0]
		default:
			a := make([]interface{}, len(c.Audiences))
			for i, s := range c.Audiences {
				a[i] = s
			}
			c.Set[audience] = a
		}
		if c.Expires != nil {
			c.Set[expires] = *c.Expires
		}
		if c.NotBefore != nil {
			c.Set[notBefore] = *c.NotBefore
		}
		if c.Issued != nil {
			c.Set[issued] = *c.Issued
		}
		if c.ID != "" {
			c.Set[id] = c.ID
		}
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	c.Raw = json.RawMessage(bytes)
	return nil
}

// Valid returns whether the claims set may be accepted
// for processing at the given moment in time.
func (c *Claims) Valid(t time.Time) bool {
	exp, expOK := c.Number(expires)
	nbf, nbfOK := c.Number(notBefore)

	n := NewNumericTime(t)
	if n == nil {
		// if there are time limits then can't be sure.
		return !expOK && !nbfOK
	}

	f := float64(*n)
	return (!expOK || exp > f) && (!nbfOK || nbf <= f)
}

// String returns the claim when present and if the representation is a JSON string.
func (c *Claims) String(name string) (value string, ok bool) {
	// try Registered first
	switch name {
	case issuer:
		value = c.Issuer
	case subject:
		value = c.Subject
	case audience:
		if len(c.Audiences) == 1 {
			return c.Audiences[0], true
		}
		if len(c.Audiences) != 0 {
			return "", false
		}
	case id:
		value = c.ID
	}
	if value != "" {
		return value, true
	}

	// fallback
	value, ok = c.Set[name].(string)
	return
}

// Number returns the claim when present and if the representation is a JSON number.
func (c *Claims) Number(name string) (value float64, ok bool) {
	// try Registered first
	switch name {
	case expires:
		if c.Expires != nil {
			return float64(*c.Expires), true
		}
	case notBefore:
		if c.NotBefore != nil {
			return float64(*c.NotBefore), true
		}
	case issued:
		if c.Issued != nil {
			return float64(*c.Issued), true
		}
	}

	// fallback
	value, ok = c.Set[name].(float64)
	return
}

// NumericTime, named NumericDate, is “A JSON numeric value representing
// the number of seconds from 1970-01-01T00:00:00Z UTC until the specified
// UTC date/time, ignoring leap seconds.”
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

// String returns the ISO representation with the empty string for nil.
func (n *NumericTime) String() string {
	if n == nil {
		return ""
	}
	return n.Time().Format("2006-01-02T15:04:05.999999999Z")
}
