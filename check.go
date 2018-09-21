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

	// create signature
	hash, err := selectHash(ECDSAAlgs, token[:firstDot], buf)
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

	return parseClaims(token[firstDot+1:lastDot], buf)
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

	// create signature
	hash, err := selectHash(HMACAlgs, token[:firstDot], buf)
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

	return parseClaims(token[firstDot+1:lastDot], buf)
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

	// create signature
	hash, err := selectHash(RSAAlgs, token[:firstDot], buf)
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

	return parseClaims(token[firstDot+1:lastDot], buf)
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

// SelectHash reads the "alg" header field from enc.
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

// ParseClaims unmarshals the payload from enc.
// Buf remains in use (by the Raw field)!
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

	// map registered claims on type match
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
