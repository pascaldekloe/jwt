package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	_ "crypto/sha256" // link binary
	_ "crypto/sha512" // link binary
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// ErrSigMiss means the signature check failed.
var ErrSigMiss = errors.New("jwt: signature mismatch")

// ErrUnsecured signals the "none" algorithm.
var ErrUnsecured = errors.New("jwt: unsecured—no signature")

var errPart = errors.New("jwt: missing base64 part")

// ECDSACheck parses a JWT and returns the claims set if, and only if, the
// signature checks out. Note that this excludes unsecured JWTs [ErrUnsecured].
// When the algorithm is not in ECDSAAlgs, then the error is ErrAlgUnk.
// See Valid to complete the verification.
func ECDSACheck(token []byte, key *ecdsa.PublicKey) (*Claims, error) {
	firstDot, lastDot, buf, err := scan(token)
	if err != nil {
		return nil, err
	}

	var c Claims

	// create signature
	hash, err := c.parseHeader(ECDSAAlgs, token[:firstDot], buf)
	if err != nil {
		return nil, err
	}
	digest := hash.New()
	digest.Write(token[:lastDot])

	// verify signature
	n, err := encoding.Decode(buf, token[lastDot+1:])
	if err != nil {
		return nil, errors.New("jwt: malformed signature: " + err.Error())
	}
	r := big.NewInt(0).SetBytes(buf[:n/2])
	s := big.NewInt(0).SetBytes(buf[n/2 : n])
	if !ecdsa.Verify(key, digest.Sum(buf[:0]), r, s) {
		return nil, ErrSigMiss
	}

	return &c, c.parseClaims(token[firstDot+1:lastDot], buf)
}

// HMACCheck parses a JWT and returns the claims set if, and only if, the
// signature checks out. Note that this excludes unsecured JWTs [ErrUnsecured].
// When the algorithm is not in HMACAlgs, then the error is ErrAlgUnk.
// See Valid to complete the verification.
func HMACCheck(token, secret []byte) (*Claims, error) {
	firstDot, lastDot, buf, err := scan(token)
	if err != nil {
		return nil, err
	}

	var c Claims

	// create signature
	hash, err := c.parseHeader(HMACAlgs, token[:firstDot], buf)
	if err != nil {
		return nil, err
	}
	digest := hmac.New(hash.New, secret)
	digest.Write(token[:lastDot])

	// verify signature
	n, err := encoding.Decode(buf, token[lastDot+1:])
	if err != nil {
		return nil, errors.New("jwt: malformed signature: " + err.Error())
	}
	if !hmac.Equal(buf[:n], digest.Sum(buf[n:n])) {
		return nil, ErrSigMiss
	}

	return &c, c.parseClaims(token[firstDot+1:lastDot], buf)
}

// RSACheck parses a JWT and returns the claims set if, and only if, the
// signature checks out. Note that this excludes unsecured JWTs [ErrUnsecured].
// When the algorithm is not in RSAAlgs, then the error is ErrAlgUnk.
// See Valid to complete the verification.
func RSACheck(token []byte, key *rsa.PublicKey) (*Claims, error) {
	firstDot, lastDot, buf, err := scan(token)
	if err != nil {
		return nil, err
	}

	var c Claims

	// create signature
	hash, err := c.parseHeader(RSAAlgs, token[:firstDot], buf)
	if err != nil {
		return nil, err
	}
	digest := hash.New()
	digest.Write(token[:lastDot])

	// verify signature
	n, err := encoding.Decode(buf, token[lastDot+1:])
	if err != nil {
		return nil, errors.New("jwt: malformed signature: " + err.Error())
	}
	if err := rsa.VerifyPKCS1v15(key, hash, digest.Sum(buf[n:n]), buf[:n]); err != nil {
		return nil, ErrSigMiss
	}

	return &c, c.parseClaims(token[firstDot+1:lastDot], buf)
}

// Scan detects the 3 base64 chunks and allocates matching buffer.
func scan(token []byte) (firstDot, lastDot int, buf []byte, err error) {
	firstDot = bytes.IndexByte(token, '.')
	lastDot = bytes.LastIndexByte(token, '.')
	if lastDot <= firstDot {
		// zero or one dot
		return 0, 0, nil, errPart
	}

	// buffer must fit largest base64 chunk
	// start with signature
	max := len(token) - lastDot
	// compare with payload
	if l := lastDot - firstDot; l > max {
		max = l
	}
	// compare with header
	if firstDot > max {
		max = firstDot
	}
	buf = make([]byte, encoding.DecodedLen(max))
	return
}

// ParseHeader decodes the enc(oded) “JOSE Header” and validates the applicability.
func (c *Claims) parseHeader(algs map[string]crypto.Hash, enc, buf []byte) (crypto.Hash, error) {
	// parse critical subset of the registered “JOSE Header Parameter Names”
	var header struct {
		Alg  string   // algorithm
		Kid  string   // key identifier
		Crit []string // extensions which must be understood and processed.
	}
	n, err := encoding.Decode(buf, enc)
	if err != nil {
		return 0, errors.New("jwt: malformed header: " + err.Error())
	}
	if err := json.Unmarshal(buf[:n], &header); err != nil {
		return 0, errors.New("jwt: malformed header: " + err.Error())
	}

	// why would anyone do this?
	if header.Alg == "none" {
		return 0, ErrUnsecured
	}

	// availability check
	hash, ok := algs[header.Alg]
	if !ok {
		return 0, ErrAlgUnk
	}
	if !hash.Available() {
		return 0, errHashLink
	}

	// “If any of the listed extension Header Parameters are not understood
	// and supported by the recipient, then the JWS is invalid.”
	// — “JSON Web Signature (JWS)” RFC 7515, subsection 4.1.11
	if len(header.Crit) != 0 {
		return 0, fmt.Errorf("jwt: unsupported critical extension in JOSE header: %q", header.Crit)
	}

	c.KeyID = header.Kid

	return hash, nil
}

// ParseClaims unmarshals the payload from enc.
// Buf remains in use (by the Raw field)!
func (c *Claims) parseClaims(enc, buf []byte) error {
	// decode payload
	n, err := encoding.Decode(buf, enc)
	if err != nil {
		return errors.New("jwt: malformed payload: " + err.Error())
	}
	buf = buf[:n]
	c.Raw = json.RawMessage(buf)

	m := make(map[string]interface{})
	c.Set = m
	if err = json.Unmarshal(buf, &m); err != nil {
		return errors.New("jwt: malformed payload: " + err.Error())
	}

	// map registered claims on type match
	if s, ok := m[issuer].(string); ok {
		delete(m, issuer)
		c.Issuer = s
	}
	if s, ok := m[subject].(string); ok {
		delete(m, subject)
		c.Subject = s
	}

	// “In the general case, the "aud" value is an array of case-sensitive
	// strings, each containing a StringOrURI value.  In the special case
	// when the JWT has one audience, the "aud" value MAY be a single
	// case-sensitive string containing a StringOrURI value.”
	switch a := m[audience].(type) {
	case []interface{}:
		allStrings := true
		for _, o := range a {
			if s, ok := o.(string); ok {
				c.Audiences = append(c.Audiences, s)
			} else {
				allStrings = false
			}
		}
		if allStrings {
			delete(m, audience)
		}

	case string:
		delete(m, audience)
		c.Audiences = []string{a}
	}

	if f, ok := m[expires].(float64); ok {
		delete(m, expires)
		t := NumericTime(f)
		c.Expires = &t
	}
	if f, ok := m[notBefore].(float64); ok {
		delete(m, notBefore)
		t := NumericTime(f)
		c.NotBefore = &t
	}
	if f, ok := m[issued].(float64); ok {
		delete(m, issued)
		t := NumericTime(f)
		c.Issued = &t
	}
	if s, ok := m[id].(string); ok {
		delete(m, id)
		c.ID = s
	}

	return nil
}
