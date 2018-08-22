package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"hash"
)

// HMACSign calls Sync and returns a new JWT.
// When the algorithm is not in HMACAlgs then the error is ErrAlgUnk.
func (c *Claims) HMACSign(alg string, secret []byte) (token []byte, err error) {
	if err := c.Sync(); err != nil {
		return nil, err
	}

	encHeader, hash, err := useAlg(alg, HMACAlgs)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(hash.New, secret)
	encSigLen := encoding.EncodedLen(hash.Size())
	token = c.newUnsignedToken(encHeader, encSigLen, mac)

	// append signature
	encoding.Encode(token[len(token)-encSigLen:], mac.Sum(nil))
	return token, nil
}

// RSASign calls Sync and returns a new JWT.
// When the algorithm is not in RSAAlgs then the error is ErrAlgUnk.
func (c *Claims) RSASign(alg string, key *rsa.PrivateKey) (token []byte, err error) {
	if err := c.Sync(); err != nil {
		return nil, err
	}

	encHeader, hash, err := useAlg(alg, RSAAlgs)
	if err != nil {
		return nil, err
	}
	h := hash.New()
	// TODO: use key.Size() as of Go 1.11 (cl103876)
	encSigLen := encoding.EncodedLen((key.N.BitLen() + 7) / 8)
	token = c.newUnsignedToken(encHeader, encSigLen, h)

	// append signature
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	encoding.Encode(token[len(token)-encSigLen:], sig)
	return token, nil
}

func (c *Claims) newUnsignedToken(encHeader string, encSigLen int, h hash.Hash) []byte {
	encClaimsLen := encoding.EncodedLen(len(c.Raw))
	token := make([]byte, len(encHeader)+encClaimsLen+encSigLen+2)

	i := copy(token, encHeader)
	token[i] = '.'
	i++
	encoding.Encode(token[i:], c.Raw)
	i += encClaimsLen
	token[i] = '.'

	h.Write(token[:i])

	return token
}

func useAlg(alg string, algs map[string]crypto.Hash) (encHeader string, h crypto.Hash, err error) {
	h, ok := algs[alg]
	if !ok {
		return "", 0, ErrAlgUnk
	}
	if !h.Available() {
		return "", 0, errHashLink
	}

	switch alg {
	case HS256:
		encHeader = "eyJhbGciOiJIUzI1NiJ9"
	case HS384:
		encHeader = "eyJhbGciOiJIUzM4NCJ9"
	case HS512:
		encHeader = "eyJhbGciOiJIUzUxMiJ9"
	case RS256:
		encHeader = "eyJhbGciOiJSUzI1NiJ9"
	case RS384:
		encHeader = "eyJhbGciOiJSUzM4NCJ9"
	case RS512:
		encHeader = "eyJhbGciOiJSUzUxMiJ9"
	default:
		encHeader = encoding.EncodeToString([]byte(`{"alg":"` + alg + `"}`))
	}

	return encHeader, h, nil
}
