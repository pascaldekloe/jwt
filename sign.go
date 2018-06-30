package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
)

// HMACSign calls Sync and returns a new JWT.
// When the algorithm is not in HMACAlgs then the error is ErrAlgUnk.
func (c *Claims) HMACSign(alg string, secret []byte) (token []byte, err error) {
	if err := c.Sync(); err != nil {
		return nil, err
	}

	header, hash, err := headerWithHash(alg, HMACAlgs)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(hash.New, secret)

	encSigLen := encoding.EncodedLen(mac.Size())
	token = make([]byte, len(header)+encoding.EncodedLen(len(c.Raw))+encSigLen+2)

	// append header + body
	offset := copy(token, header)
	token[offset] = '.'
	offset++
	encoding.Encode(token[offset:], c.Raw)
	offset = len(token) - encSigLen - 1

	mac.Write(token[:offset])

	// append signature
	token[offset] = '.'
	offset++
	encoding.Encode(token[offset:], mac.Sum(nil))

	return token, nil
}

// RSASign calls Sync and returns a new JWT.
// When the algorithm is not in RSAAlgs then the error is ErrAlgUnk.
func (c *Claims) RSASign(alg string, key *rsa.PrivateKey) (token []byte, err error) {
	if err := c.Sync(); err != nil {
		return nil, err
	}

	header, hash, err := headerWithHash(alg, RSAAlgs)
	if err != nil {
		return nil, err
	}

	// replace with key.Size as of Go 1.11 (cl103876)
	encSigLen := encoding.EncodedLen((key.N.BitLen() + 7) / 8)
	token = make([]byte, len(header)+encoding.EncodedLen(len(c.Raw))+encSigLen+2)

	// append header + body
	offset := copy(token, header)
	token[offset] = '.'
	offset++
	encoding.Encode(token[offset:], c.Raw)
	offset = len(token) - encSigLen - 1

	// sign
	h := hash.New()
	h.Write(token[:offset])
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	// append signature
	token[offset] = '.'
	offset++
	encoding.Encode(token[offset:], sig)

	return token, nil
}

// HeaderWithHash returns the base64 encoded header including hash algorithm.
func headerWithHash(alg string, algs map[string]crypto.Hash) (string, crypto.Hash, error) {
	hash, ok := algs[alg]
	if !ok {
		return "", 0, ErrAlgUnk
	}
	if !hash.Available() {
		return "", 0, errHashLink
	}

	var header string
	switch alg {
	case HS256:
		header = "eyJhbGciOiJIUzI1NiJ9"
	case HS384:
		header = "eyJhbGciOiJIUzM4NCJ9"
	case HS512:
		header = "eyJhbGciOiJIUzUxMiJ9"
	case RS256:
		header = "eyJhbGciOiJSUzI1NiJ9"
	case RS384:
		header = "eyJhbGciOiJSUzM4NCJ9"
	case RS512:
		header = "eyJhbGciOiJSUzUxMiJ9"
	default:
		header = encoding.EncodeToString([]byte(`{"alg":"` + alg + `"}`))
	}

	return header, hash, nil
}
