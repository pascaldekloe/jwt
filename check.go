package jwt

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	_ "crypto/sha256" // link
	_ "crypto/sha512" // link
	"encoding/json"
	"errors"
)

// ErrSigMiss means the signature check failed.
var ErrSigMiss = errors.New("jwt: signature mismatch")

// ErrUnsecured signals the "none" algorithm.
var ErrUnsecured = errors.New("jwt: unsecured—no signature")

var errPart = errors.New("jwt: missing base64 part")

// HMACCheck returns the claims set if, and only if, the signature checks out.
// Note that this excludes unsecured JWTs [ErrUnsecured].
func HMACCheck(jwt, secret []byte) (*Claims, error) {
	firstDot, lastDot, buf, err := scan(jwt)
	if err != nil {
		return nil, err
	}

	// create signature
	hash, err := selectHash(HMACAlgs, jwt[:firstDot], buf)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(hash.New, secret)
	mac.Write(jwt[:lastDot])

	// verify signature
	n, err := encoding.Decode(buf, jwt[lastDot+1:])
	if err != nil {
		return nil, errors.New("jwt: malformed signature: " + err.Error())
	}
	if !hmac.Equal(buf[:n], mac.Sum(buf[n:n])) {
		return nil, ErrSigMiss
	}

	return parseClaims(jwt[firstDot+1:lastDot], buf)
}

// RSACheck returns the claims set if, and only if, the signature checks out.
// Note that this excludes unsecured JWTs [ErrUnsecured].
func RSACheck(jwt []byte, key *rsa.PublicKey) (*Claims, error) {
	firstDot, lastDot, buf, err := scan(jwt)
	if err != nil {
		return nil, err
	}

	// create signature
	hash, err := selectHash(RSAAlgs, jwt[:firstDot], buf)
	if err != nil {
		return nil, err
	}
	h := hash.New()
	h.Write(jwt[:lastDot])

	// verify signature
	n, err := encoding.Decode(buf, jwt[lastDot+1:])
	if err != nil {
		return nil, errors.New("jwt: malformed signature: " + err.Error())
	}
	if err := rsa.VerifyPKCS1v15(key, hash, h.Sum(buf[n:n]), buf[:n]); err != nil {
		return nil, ErrSigMiss
	}

	return parseClaims(jwt[firstDot+1:lastDot], buf)
}

// Scan detects the 3 base64 chunks and allocates matching buffer.
func scan(jwt []byte) (firstDot, lastDot int, buf []byte, err error) {
	firstDot = bytes.IndexByte(jwt, '.')
	lastDot = bytes.LastIndexByte(jwt, '.')
	if lastDot <= firstDot {
		// zero or one dot
		return 0, 0, nil, errPart
	}

	// buffer must fit largest base64 chunk
	// start with signature
	max := len(jwt) - lastDot
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

// SelectHash reads the "alg" field from the header enc.
func selectHash(algs map[string]crypto.Hash, enc, buf []byte) (crypto.Hash, error) {
	// parse header
	var header struct {
		Alg string `json:"alg"`
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

	return hash, nil
}

// ParseClaims unmarshals the payload from the payload enc.
func parseClaims(enc, buf []byte) (*Claims, error) {
	// decode payload
	n, err := encoding.Decode(buf, enc)
	if err != nil {
		return nil, errors.New("jwt: malformed payload: " + err.Error())
	}
	buf = buf[:n]

	c := &Claims{Raw: json.RawMessage(buf)}

	c.Set = make(map[string]interface{})
	if err = json.Unmarshal(buf, &c.Set); err != nil {
		return nil, errors.New("jwt: malformed payload: " + err.Error())
	}

	// map registerd claims on type match
	if s, ok := c.Set["iss"].(string); ok {
		c.Issuer = s
	}
	if s, ok := c.Set["sub"].(string); ok {
		c.Subject = s
	}
	if s, ok := c.Set["aud"].(string); ok {
		c.Audience = s
	}
	if f, ok := c.Set["exp"].(float64); ok {
		t := NumericTime(f)
		c.Expires = &t
	}
	if f, ok := c.Set["nbf"].(float64); ok {
		t := NumericTime(f)
		c.NotBefore = &t
	}
	if f, ok := c.Set["iat"].(float64); ok {
		t := NumericTime(f)
		c.Issued = &t
	}
	if s, ok := c.Set["jti"].(string); ok {
		c.ID = s
	}

	return c, nil
}
