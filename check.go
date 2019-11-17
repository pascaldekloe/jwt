package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
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

var errPart = errors.New("jwt: missing base64 part")

// ParseWithoutCheck skips the signature validation.
func ParseWithoutCheck(token []byte) (*Claims, error) {
	var c Claims
	firstDot, lastDot, sig, _, err := c.scan(token)
	if err != nil {
		return nil, err
	}

	return &c, c.applyPayload(token[firstDot+1:lastDot], sig)
}

// ECDSACheck parses a JWT if, and only if, the signature checks out.
// The return is an AlgError when the algorithm is not in ECDSAAlgs.
// See Valid to complete the verification.
func ECDSACheck(token []byte, key *ecdsa.PublicKey) (*Claims, error) {
	var c Claims
	firstDot, lastDot, sig, alg, err := c.scan(token)
	if err != nil {
		return nil, err
	}

	hash, err := hashLookup(alg, ECDSAAlgs)
	if err != nil {
		return nil, err
	}
	digest := hash.New()
	digest.Write(token[:lastDot])

	r := big.NewInt(0).SetBytes(sig[:len(sig)/2])
	s := big.NewInt(0).SetBytes(sig[len(sig)/2:])
	if !ecdsa.Verify(key, digest.Sum(sig[:0]), r, s) {
		return nil, ErrSigMiss
	}

	return &c, c.applyPayload(token[firstDot+1:lastDot], sig)
}

// EdDSACheck parses a JWT if, and only if, the signature checks out.
// See Valid to complete the verification.
func EdDSACheck(token []byte, key ed25519.PublicKey) (*Claims, error) {
	var c Claims
	firstDot, lastDot, sig, alg, err := c.scan(token)
	if err != nil {
		return nil, err
	}

	if alg != EdDSA {
		return nil, AlgError(alg)
	}

	if !ed25519.Verify(key, token[:lastDot], sig) {
		return nil, ErrSigMiss
	}

	return &c, c.applyPayload(token[firstDot+1:lastDot], sig)
}

// HMACCheck parses a JWT if, and only if, the signature checks out.
// The return is an AlgError when the algorithm is not in HMACAlgs.
// See Valid to complete the verification.
func HMACCheck(token, secret []byte) (*Claims, error) {
	if len(secret) == 0 {
		return nil, errNoSecret
	}

	var c Claims
	firstDot, lastDot, sig, alg, err := c.scan(token)
	if err != nil {
		return nil, err
	}

	hash, err := hashLookup(alg, HMACAlgs)
	if err != nil {
		return nil, err
	}
	digest := hmac.New(hash.New, secret)
	digest.Write(token[:lastDot])

	if !hmac.Equal(sig, digest.Sum(sig[len(sig):])) {
		return nil, ErrSigMiss
	}

	return &c, c.applyPayload(token[firstDot+1:lastDot], sig)
}

// RSACheck parses a JWT if, and only if, the signature checks out.
// The return is an AlgError when the algorithm is not in RSAAlgs.
// See Valid to complete the verification.
func RSACheck(token []byte, key *rsa.PublicKey) (*Claims, error) {
	var c Claims
	firstDot, lastDot, sig, alg, err := c.scan(token)
	if err != nil {
		return nil, err
	}

	hash, err := hashLookup(alg, RSAAlgs)
	if err != nil {
		return nil, err
	}
	digest := hash.New()
	digest.Write(token[:lastDot])

	if alg != "" && alg[0] == 'P' {
		err = rsa.VerifyPSS(key, hash, digest.Sum(sig[len(sig):]), sig, nil)
	} else {
		err = rsa.VerifyPKCS1v15(key, hash, digest.Sum(sig[len(sig):]), sig)
	}
	if err != nil {
		return nil, ErrSigMiss
	}

	return &c, c.applyPayload(token[firstDot+1:lastDot], sig)
}

func (c *Claims) scan(token []byte) (firstDot, lastDot int, sig []byte, alg string, err error) {
	firstDot = bytes.IndexByte(token, '.')
	lastDot = bytes.LastIndexByte(token, '.')
	if lastDot <= firstDot {
		// zero or one dot
		return 0, 0, nil, "", errPart
	}

	buf := make([]byte, encoding.DecodedLen(len(token)))
	n, err := encoding.Decode(buf, token[:firstDot])
	if err != nil {
		return 0, 0, nil, "", fmt.Errorf("jwt: malformed JOSE header: %w", err)
	}

	var header struct {
		Kid  string        `json:"kid"`
		Alg  string        `json:"alg"`
		Crit []interface{} `json:"crit"`
	}
	if err := json.Unmarshal(buf[:n], &header); err != nil {
		return 0, 0, nil, "", fmt.Errorf("jwt: malformed JOSE header: %w", err)
	}

	alg = header.Alg
	c.KeyID = header.Kid
	// “If any of the listed extension Header Parameters are not understood
	// and supported by the recipient, then the JWS is invalid. […]
	// Producers MUST NOT use the empty list "[]" as the "crit" value.”
	// — “JSON Web Signature (JWS)” RFC 7515, subsection 4.1.11
	if header.Crit != nil {
		return 0, 0, nil, "", fmt.Errorf("jwt: unsupported critical extension in JOSE header: %q", header.Crit)
	}

	// signature
	n, err = encoding.Decode(buf, token[lastDot+1:])
	if err != nil {
		return 0, 0, nil, "", fmt.Errorf("jwt: malformed signature: %w", err)
	}
	sig = buf[:n]

	return
}

// Buf remains in use as the Raw field.
func (c *Claims) applyPayload(encoded, buf []byte) error {
	buf = buf[:cap(buf)]
	n, err := encoding.Decode(buf, encoded)
	if err != nil {
		return fmt.Errorf("jwt: malformed payload: %w", err)
	}
	buf = buf[:n]
	c.Raw = json.RawMessage(buf)
	if err = json.Unmarshal(buf, &c.Set); err != nil {
		return fmt.Errorf("jwt: malformed payload: %w", err)
	}

	// move from Set to Registered on type match
	m := c.Set
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
		c.Expires = (*NumericTime)(&f)
	}
	if f, ok := m[notBefore].(float64); ok {
		delete(m, notBefore)
		c.NotBefore = (*NumericTime)(&f)
	}
	if f, ok := m[issued].(float64); ok {
		delete(m, issued)
		c.Issued = (*NumericTime)(&f)
	}
	if s, ok := m[id].(string); ok {
		delete(m, id)
		c.ID = s
	}

	return nil
}
