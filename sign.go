package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"hash"
)

// ECDSASign calls Sync and returns a new JWT.
// When the algorithm is not in ECDSAAlgs then the error is ErrAlgUnk.
// The caller must use the correct key for the respective algorithm (P-256 for
// ES256, P-384 for ES384 and P-521 for ES512) or risk malformed token production.
func (c *Claims) ECDSASign(alg string, key *ecdsa.PrivateKey) (token []byte, err error) {
	if err := c.Sync(); err != nil {
		return nil, err
	}

	// signature contains pair (r, s) as per RFC 7518 section 3.4
	sig := make([]byte, 2*((key.Curve.Params().BitSize+7)/8))
	encSigLen := encoding.EncodedLen(len(sig))

	encHeader, hash, err := useAlg(alg, ECDSAAlgs)
	if err != nil {
		return nil, err
	}
	digest := hash.New()
	token = c.newUnsignedToken(encHeader, encSigLen, digest)

	// create signature
	r, s, err := ecdsa.Sign(rand.Reader, key, digest.Sum(nil))
	if err != nil {
		return nil, err
	}

	// algin right with big-endian order
	rBytes, sBytes := r.Bytes(), s.Bytes()
	copy(sig[(len(sig)/2)-len(rBytes):], rBytes)
	copy(sig[len(sig)-len(sBytes):], sBytes)

	// append signature
	encoding.Encode(token[len(token)-encSigLen:], sig)
	return token, nil
}

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
	digest := hmac.New(hash.New, secret)
	encSigLen := encoding.EncodedLen(digest.Size())
	token = c.newUnsignedToken(encHeader, encSigLen, digest)

	// append signature
	encoding.Encode(token[len(token)-encSigLen:], digest.Sum(nil))
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
	digest := hash.New()
	// TODO: use key.Size() as of Go 1.11 (cl103876)
	encSigLen := encoding.EncodedLen((key.N.BitLen() + 7) / 8)
	token = c.newUnsignedToken(encHeader, encSigLen, digest)

	// append signature
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest.Sum(nil))
	if err != nil {
		return nil, err
	}
	encoding.Encode(token[len(token)-encSigLen:], sig)
	return token, nil
}

func (c *Claims) newUnsignedToken(encHeader string, encSigLen int, digest hash.Hash) []byte {
	encClaimsLen := encoding.EncodedLen(len(c.Raw))
	token := make([]byte, len(encHeader)+encClaimsLen+encSigLen+2)

	i := copy(token, encHeader)
	token[i] = '.'
	i++
	encoding.Encode(token[i:], c.Raw)
	i += encClaimsLen
	token[i] = '.'

	digest.Write(token[:i])

	return token
}

func useAlg(alg string, algs map[string]crypto.Hash) (encHeader string, hash crypto.Hash, err error) {
	hash, ok := algs[alg]
	if !ok {
		return "", 0, ErrAlgUnk
	}
	if !hash.Available() {
		return "", 0, errHashLink
	}

	switch alg {
	case ES256:
		encHeader = "eyJhbGciOiJFUzI1NiJ9"
	case ES384:
		encHeader = "eyJhbGciOiJFUzM4NCJ9"
	case ES512:
		encHeader = "eyJhbGciOiJFUzUxMiJ9"
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

	return encHeader, hash, nil
}
