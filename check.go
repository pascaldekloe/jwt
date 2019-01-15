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
	return check(token, func(content, sig []byte, header *header) error {
		hash, err := header.match(ECDSAAlgs)
		if err != nil {
			return err
		}

		r := big.NewInt(0).SetBytes(sig[:len(sig)/2])
		s := big.NewInt(0).SetBytes(sig[len(sig)/2:])
		digest := hash.New()
		digest.Write(content)
		if !ecdsa.Verify(key, digest.Sum(sig[:0]), r, s) {
			return ErrSigMiss
		}
		return nil
	})
}

// HMACCheck parses a JWT and returns the claims set if, and only if, the
// signature checks out. Note that this excludes unsecured JWTs [ErrUnsecured].
// When the algorithm is not in HMACAlgs, then the error is ErrAlgUnk.
// See Valid to complete the verification.
func HMACCheck(token, secret []byte) (*Claims, error) {
	return check(token, func(content, sig []byte, header *header) error {
		hash, err := header.match(HMACAlgs)
		if err != nil {
			return err
		}

		digest := hmac.New(hash.New, secret)
		digest.Write(content)
		if !hmac.Equal(sig, digest.Sum(sig[len(sig):])) {
			return ErrSigMiss
		}
		return nil
	})
}

// RSACheck parses a JWT and returns the claims set if, and only if, the
// signature checks out. Note that this excludes unsecured JWTs [ErrUnsecured].
// When the algorithm is not in RSAAlgs, then the error is ErrAlgUnk.
// See Valid to complete the verification.
func RSACheck(token []byte, key *rsa.PublicKey) (*Claims, error) {
	return check(token, func(content, sig []byte, header *header) error {
		hash, err := header.match(RSAAlgs)
		if err != nil {
			return err
		}

		digest := hash.New()
		digest.Write(content)

		if header.Alg[0] == 'P' {
			err = rsa.VerifyPSS(key, hash, digest.Sum(sig[len(sig):]), sig, nil)
		} else {
			err = rsa.VerifyPKCS1v15(key, hash, digest.Sum(sig[len(sig):]), sig)
		}
		if err != nil {
			return ErrSigMiss
		}
		return nil
	})
}

func check(token []byte, verifySig func(content, sig []byte, header *header) error) (*Claims, error) {
	firstDot := bytes.IndexByte(token, '.')
	lastDot := bytes.LastIndexByte(token, '.')
	if lastDot <= firstDot {
		// zero or one dot
		return nil, errPart
	}

	buf := make([]byte, encoding.DecodedLen(len(token)))

	n, err := encoding.Decode(buf, token[:firstDot])
	if err != nil {
		return nil, errors.New("jwt: malformed header: " + err.Error())
	}

	header := new(header)
	if err := json.Unmarshal(buf[:n], header); err != nil {
		return nil, errors.New("jwt: malformed header: " + err.Error())
	}

	// “If any of the listed extension Header Parameters are not understood
	// and supported by the recipient, then the JWS is invalid.”
	// — “JSON Web Signature (JWS)” RFC 7515, subsection 4.1.11
	if len(header.Crit) != 0 {
		return nil, fmt.Errorf("jwt: unsupported critical extension in JOSE header: %q", header.Crit)
	}

	// verify signature
	n, err = encoding.Decode(buf, token[lastDot+1:])
	if err != nil {
		return nil, errors.New("jwt: malformed signature: " + err.Error())
	}
	err = verifySig(token[:lastDot], buf[:n], header)
	if err != nil {
		return nil, err
	}

	claims, err := parseClaims(token[firstDot+1:lastDot], buf)
	if err != nil {
		return nil, err
	}

	claims.KeyID = header.Kid
	return claims, nil
}

// Header is a critical subset of the registered “JOSE Header Parameter Names”.
type header struct {
	Alg  string   // algorithm
	Kid  string   // key identifier
	Crit []string // extensions which must be understood and processed
}

func (h *header) match(algs map[string]crypto.Hash) (crypto.Hash, error) {
	// why would anyone do this?
	if h.Alg == "none" {
		return 0, ErrUnsecured
	}

	// availability check
	hash, ok := algs[h.Alg]
	if !ok {
		return 0, ErrAlgUnk
	}
	if !hash.Available() {
		return 0, errHashLink
	}
	return hash, nil
}

// Buf remains in use (by the Raw field)!
func parseClaims(enc, buf []byte) (*Claims, error) {
	n, err := encoding.Decode(buf, enc)
	if err != nil {
		return nil, errors.New("jwt: malformed payload: " + err.Error())
	}
	buf = buf[:n]

	// construct result
	c := &Claims{
		Raw: json.RawMessage(buf),
		Set: make(map[string]interface{}),
	}
	if err = json.Unmarshal(buf, &c.Set); err != nil {
		return nil, errors.New("jwt: malformed payload: " + err.Error())
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

	return c, nil
}
