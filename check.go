package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
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
var ErrSigMiss = errors.New("jwt: signature mismatch")

// ErrUnsecured signals the "none" algorithm.
var ErrUnsecured = errors.New("jwt: unsecured—no signature")

var (
	errPart = errors.New("jwt: missing base64 part")
	errLink = errors.New("jwt: hash function not linked into binary")
)

// HMACAlgs is the HMAC hash algorithm registration.
// When adding additional entries you also need to
// import the respective packages to link the hash
// function into the binary [crypto.Hash.Available].
var HMACAlgs = map[string]crypto.Hash{
	HS256: crypto.SHA256,
	HS384: crypto.SHA384,
	HS512: crypto.SHA512,
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
		return nil, errors.New("jwt: malformed " + err.Error())
	}

	// verify signature
	if h.Alg == "none" {
		return nil, ErrUnsecured
	}
	alg, ok := HMACAlgs[h.Alg]
	if !ok {
		return nil, fmt.Errorf("jwt: unknown HMAC algorithm %q", h.Alg)
	}
	if !alg.Available() {
		return nil, errLink
	}
	mac := hmac.New(alg.New, secret)
	mac.Write([]byte(body))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, ErrSigMiss
	}

	return parseClaims(body[i+1:])
}

// RSAAlgs is the RSA hash algorithm registration.
// When adding additional entries you also need to
// import the respective packages to link the hash
// function into the binary [crypto.Hash.Available].
var RSAAlgs = map[string]crypto.Hash{
	RS256: crypto.SHA256,
	RS384: crypto.SHA384,
	RS512: crypto.SHA512,
}

// RSACheck returns the claims set if, and only if, the signature checks out.
// Note that this excludes unsecured JWTs [ErrUnsecured].
func RSACheck(jwt string, key *rsa.PublicKey) (*Claims, error) {
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
		return nil, errors.New("jwt: malformed " + err.Error())
	}

	// verify signature
	if h.Alg == "none" {
		return nil, ErrUnsecured
	}
	alg, ok := RSAAlgs[h.Alg]
	if !ok {
		return nil, fmt.Errorf("jwt: unknown RSA algorithm %q", h.Alg)
	}
	if !alg.Available() {
		return nil, errLink
	}
	hash := alg.New()
	hash.Write([]byte(body))
	if err := rsa.VerifyPKCS1v15(key, alg, hash.Sum(nil), sig); err != nil {
		return nil, ErrSigMiss
	}

	return parseClaims(body[i+1:])
}

func parseClaims(base64 string) (*Claims, error) {
	bytes, err := decode(base64)
	if err != nil {
		return nil, err
	}
	c := &Claims{
		Raw: json.RawMessage(bytes),
		Set: make(map[string]interface{}),
	}
	if err = json.Unmarshal(bytes, &c.Registered); err != nil {
		return nil, errors.New("jwt: malformed " + err.Error())
	}
	if err = json.Unmarshal(bytes, &c.Set); err != nil {
		return nil, errors.New("jwt: malformed " + err.Error())
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
		return nil, errors.New("jwt: malformed " + err.Error())
	}
	return buf[:n], nil
}
