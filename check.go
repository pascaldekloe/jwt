// Package jwt implements JWT verification.
// See "JSON Web Token (JWT)" RFC 7519
// and "JSON Web Signature (JWS)" RFC 7515.
package jwt

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type header struct {
	Alg string `json:"alg"`
}

// ErrSigMiss means the signature check failed.
var ErrSigMiss = errors.New("signature mismatch")

// ErrUnsecured means the JWT has no signature.
var ErrUnsecured = errors.New("unsecured JWT")

var (
	errPart = errors.New("missing base64 part")
	errLink = errors.New("hash function not linked into binary")
)

// HMACAlgs is the hash algorithm registration.
// When adding additional entries you also need to
// import the respective packages to link the hash
// function into the binary [crypto.Hash.Available].
var HMACAlgs = map[string]crypto.Hash{
	"HS256": crypto.SHA256,
}

// HMACCheck returns the claims set if, and only if, the signature checks out.
// Note that this excludes unsecured JWTs [ErrUnsecured].
func HMACCheck(jwt string, secret []byte) (*Claims, error) {
	// parse signature
	i := strings.LastIndexByte(jwt, '.')
	if i < 0 {
		return nil, errPart
	}
	sig, err := decode(jwt[i+1:])
	if err != nil {
		return nil, err
	}

	body := jwt[:i]

	// parse header
	i = strings.IndexByte(body, '.')
	if i < 0 {
		return nil, errPart
	}
	bytes, err := decode(body[:i])
	if err != nil {
		return nil, err
	}
	var h header
	if err := json.Unmarshal(bytes, &h); err != nil {
		return nil, err
	}

	// verify signature
	if h.Alg == "none" {
		return nil, ErrUnsecured
	}
	alg, ok := HMACAlgs[h.Alg]
	if !ok {
		return nil, fmt.Errorf("alg %q not supported", h.Alg)
	}
	if !alg.Available() {
		return nil, errLink
	}
	mac := hmac.New(alg.New, secret)
	mac.Write([]byte(body))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, ErrSigMiss
	}

	// parse claims
	bytes, err = decode(body[i+1:])
	if err != nil {
		return nil, err
	}
	c := &Claims{
		Raw: json.RawMessage(bytes),
		Set: make(map[string]interface{}),
	}
	if err = json.Unmarshal(bytes, &c.Registered); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(bytes, &c.Set); err != nil {
		return nil, err
	}
	return c, nil
}

// decode base64url without padding conform RFC 7515, appendix C.
func decode(s string) ([]byte, error) {
	bytes := make([]byte, len(s), len(s)+2)
	copy(bytes, s)
	for i, b := range bytes {
		switch b {
		case '-':
			bytes[i] = '+' // 62nd char of encoding
		case '_':
			bytes[i] = '/' // 63rd char of encoding
		}
	}

	// add padding
	switch len(bytes) % 4 {
	case 2:
		bytes = append(bytes, '=', '=')
	case 3:
		bytes = append(bytes, '=')
	}

	buf := make([]byte, base64.StdEncoding.DecodedLen(len(bytes)))
	n, err := base64.StdEncoding.Decode(buf, bytes)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
