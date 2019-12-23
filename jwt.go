// Package jwt implements “JSON Web Token (JWT)” RFC 7519.
// Signatures only; no unsecured nor encrypted tokens.
package jwt

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Algorithm Identification Tokens
const (
	EdDSA = "EdDSA" // EdDSA signature algorithms
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

// Algorithm support is configured with hash registrations.
var (
	ECDSAAlgs = map[string]crypto.Hash{
		ES256: crypto.SHA256,
		ES384: crypto.SHA384,
		ES512: crypto.SHA512,
	}
	HMACAlgs = map[string]crypto.Hash{
		HS256: crypto.SHA256,
		HS384: crypto.SHA384,
		HS512: crypto.SHA512,
	}
	RSAAlgs = map[string]crypto.Hash{
		PS256: crypto.SHA256,
		PS384: crypto.SHA384,
		PS512: crypto.SHA512,
		RS256: crypto.SHA256,
		RS384: crypto.SHA384,
		RS512: crypto.SHA512,
	}
)

// See crypto.Hash.Available.
var errHashLink = errors.New("jwt: hash function not linked into binary")

func hashLookup(alg string, algs map[string]crypto.Hash) (crypto.Hash, error) {
	// availability check
	hash, ok := algs[alg]
	if !ok {
		return 0, AlgError(alg)
	}
	if !hash.Available() {
		return 0, errHashLink
	}
	return hash, nil
}

// AlgError signals that the specified algorithm is not in use.
type AlgError string

// Error honors the error interface.
func (e AlgError) Error() string {
	return fmt.Sprintf("jwt: algorithm %q not in use", string(e))
}

// ErrNoSecret protects against programming and configuration mistakes.
var errNoSecret = errors.New("jwt: empty secret rejected")

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

// Registered “JSON Web Token Claims” has a subset of the IANA registration.
// See <https://www.iana.org/assignments/jwt/claims.csv> for the full listing.
//
// Each field is optional—there are no required claims. The string values are
// case sensitive.
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

// AcceptAudience verifies the applicability of the audience identified with
// stringOrURI. Any stringOrURI is accepted on absence of the audience claim.
func (r *Registered) AcceptAudience(stringOrURI string) bool {
	for _, a := range r.Audiences {
		if stringOrURI == a {
			return true
		}
	}
	return len(r.Audiences) == 0
}

// Claims are the (signed) statements of a JWT.
type Claims struct {
	// Registered field values take precedence.
	Registered

	// Set maps claims by name, for usecases beyond the Registered fields.
	// The Sign methods copy each non-zero Registered value into Set when
	// the map is not nil. The Check methods map claims in Set if the name
	// doesn't match any of the Registered, or if the data type won't fit.
	// Entries are treated conform the encoding/json package.
	//
	//	bool, for JSON booleans
	//	float64, for JSON numbers
	//	string, for JSON strings
	//	[]interface{}, for JSON arrays
	//	map[string]interface{}, for JSON objects
	//	nil for JSON null
	//
	Set map[string]interface{}

	// Raw encoding as is within the token. This field is read-only.
	Raw json.RawMessage

	// “The "kid" (key ID) Header Parameter is a hint indicating which key
	// was used to secure the JWS. This parameter allows originators to
	// explicitly signal a change of key to recipients. The structure of the
	// "kid" value is unspecified. Its value MUST be a case-sensitive
	// string. Use of this Header Parameter is OPTIONAL.”
	// — “JSON Web Signature (JWS)” RFC 7515, subsection 4.1.4
	KeyID string
}

// Valid returns whether the claims set may be accepted for processing at the
// given moment in time. If the time is zero, then Valid returns whether there
// are no time constraints.
func (c *Claims) Valid(t time.Time) bool {
	exp, expOK := c.Number(expires)
	nbf, nbfOK := c.Number(notBefore)

	n := NewNumericTime(t)
	if n == nil {
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

// NumericTime implements NumericDate: “A JSON numeric value representing
// the number of seconds from 1970-01-01T00:00:00Z UTC until the specified
// UTC date/time, ignoring leap seconds.”
type NumericTime float64

// NewNumericTime returns the the corresponding representation with nil for the
// zero value. Do t.Round(time.Second) for slighly smaller token production and
// compatibility. See the bugs section for details.
func NewNumericTime(t time.Time) *NumericTime {
	if t.IsZero() {
		return nil
	}

	// BUG(pascaldekloe): Some broken implementations fail to parse tokens
	// with fractions in Registered.Expires, .NotBefore or .Issued. Round to
	// seconds—like NewNumericDate(time.Now().Round(time.Seconds))—for
	// compatibility.

	n := NumericTime(float64(t.UnixNano()) / 1e9)
	return &n
}

// Time returns the Go mapping with the zero value for nil.
func (n *NumericTime) Time() time.Time {
	if n == nil {
		return time.Time{}
	}
	return time.Unix(0, int64(float64(*n)*float64(time.Second))).UTC()
}

// String returns the ISO representation or the empty string for nil.
func (n *NumericTime) String() string {
	if n == nil {
		return ""
	}
	return n.Time().Format(time.RFC3339Nano)
}
