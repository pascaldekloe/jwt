package jwt

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"hash"
	"strconv"
)

// ECDSASign updates the Raw field and returns a new JWT.
// The return is an AlgError when alg is not in ECDSAAlgs.
// The caller must use the correct key for the respective algorithm (P-256 for
// ES256, P-384 for ES384 and P-521 for ES512) or risk malformed token production.
func (c *Claims) ECDSASign(alg string, key *ecdsa.PrivateKey) (token []byte, err error) {
	if err := c.sync(); err != nil {
		return nil, err
	}

	hash, err := hashLookup(alg, ECDSAAlgs)
	if err != nil {
		return nil, err
	}
	digest := hash.New()

	// signature contains pair (r, s) as per RFC 7518 section 3.4
	sigLen := 2 * ((key.Curve.Params().BitSize + 7) / 8)
	encSigLen := encoding.EncodedLen(sigLen)
	token = c.newToken(alg, encSigLen, digest)

	// create signature
	r, s, err := ecdsa.Sign(rand.Reader, key, digest.Sum(nil))
	if err != nil {
		return nil, err
	}

	// append signature
	sig := make([]byte, sigLen)
	// algin right with big-endian order
	rBytes, sBytes := r.Bytes(), s.Bytes()
	copy(sig[(len(sig)/2)-len(rBytes):], rBytes)
	copy(sig[len(sig)-len(sBytes):], sBytes)
	encoding.Encode(token[len(token)-encSigLen:], sig)
	return token, nil
}

// HMACSign updates the Raw field and returns a new JWT.
// The return is an AlgError when alg is not in HMACAlgs.
func (c *Claims) HMACSign(alg string, secret []byte) (token []byte, err error) {
	if err := c.sync(); err != nil {
		return nil, err
	}

	hash, err := hashLookup(alg, HMACAlgs)
	if err != nil {
		return nil, err
	}
	digest := hmac.New(hash.New, secret)

	encSigLen := encoding.EncodedLen(digest.Size())
	token = c.newToken(alg, encSigLen, digest)

	// append signature
	encoding.Encode(token[len(token)-encSigLen:], digest.Sum(nil))
	return token, nil
}

// RSASign updates the Raw field and returns a new JWT.
// The return is an AlgError when alg is not in RSAAlgs.
func (c *Claims) RSASign(alg string, key *rsa.PrivateKey) (token []byte, err error) {
	if err := c.sync(); err != nil {
		return nil, err
	}

	hash, err := hashLookup(alg, RSAAlgs)
	if err != nil {
		return nil, err
	}
	digest := hash.New()

	encSigLen := encoding.EncodedLen(key.Size())
	token = c.newToken(alg, encSigLen, digest)

	// append signature
	var sig []byte
	if alg[0] == 'P' {
		sig, err = rsa.SignPSS(rand.Reader, key, hash, digest.Sum(nil), nil)
	} else {
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, hash, digest.Sum(nil))
	}
	if err != nil {
		return nil, err
	}
	encoding.Encode(token[len(token)-encSigLen:], sig)
	return token, nil
}

// NewToken returns a new JWT with the signature bytes still unset.
func (c *Claims) newToken(alg string, encSigLen int, digest hash.Hash) []byte {
	encHeader := c.formatHeader(alg)

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

// FormatHeader encodes the JOSE header.
func (c *Claims) formatHeader(alg string) string {
	if kid := c.KeyID; kid != "" {
		buf := make([]byte, 7, 24+len(kid))
		copy(buf, `{"alg":`)
		buf = strconv.AppendQuote(buf, alg)
		buf = append(buf, `,"kid":`...)
		buf = strconv.AppendQuote(buf, kid)
		buf = append(buf, '}')

		return encoding.EncodeToString(buf)
	}

	switch alg {
	case ES256:
		return "eyJhbGciOiJFUzI1NiJ9"
	case ES384:
		return "eyJhbGciOiJFUzM4NCJ9"
	case ES512:
		return "eyJhbGciOiJFUzUxMiJ9"
	case HS256:
		return "eyJhbGciOiJIUzI1NiJ9"
	case HS384:
		return "eyJhbGciOiJIUzM4NCJ9"
	case HS512:
		return "eyJhbGciOiJIUzUxMiJ9"
	case PS256:
		return "eyJhbGciOiJQUzI1NiJ9"
	case PS384:
		return "eyJhbGciOiJQUzM4NCJ9"
	case PS512:
		return "eyJhbGciOiJQUzUxMiJ9"
	case RS256:
		return "eyJhbGciOiJSUzI1NiJ9"
	case RS384:
		return "eyJhbGciOiJSUzM4NCJ9"
	case RS512:
		return "eyJhbGciOiJSUzUxMiJ9"
	default:
		buf := make([]byte, 7, 14)
		copy(buf, `{"alg":`)
		buf = strconv.AppendQuote(buf, alg)
		buf = append(buf, '}')

		return encoding.EncodeToString(buf)
	}
}
