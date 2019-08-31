package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
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

	// signature contains pair (r, s) as per RFC 7518, subsection 3.4
	paramLen := (key.Curve.Params().BitSize + 7) / 8
	token = c.newToken(alg, encoding.EncodedLen(paramLen*2))
	digest.Write(token)
	token = append(token, '.')

	r, s, err := ecdsa.Sign(rand.Reader, key, digest.Sum(nil))
	if err != nil {
		return nil, err
	}

	sig := token[len(token):cap(token)]
	i := len(sig)
	for _, word := range s.Bits() {
		for bitCount := strconv.IntSize; bitCount > 0; bitCount -= 8 {
			i--
			sig[i] = byte(word)
			word >>= 8
		}
	}
	// i might have exceeded paramLen due to the word size
	i = len(sig) - paramLen
	for _, word := range r.Bits() {
		for bitCount := strconv.IntSize; bitCount > 0; bitCount -= 8 {
			i--
			sig[i] = byte(word)
			word >>= 8
		}
	}

	// encoder won't overhaul source space
	encoding.Encode(sig, sig[len(sig)-2*paramLen:])

	return token[:cap(token)], nil
}

// EdDSASign updates the Raw field and returns a new JWT.
func (c *Claims) EdDSASign(key ed25519.PrivateKey) (token []byte, err error) {
	if err := c.sync(); err != nil {
		return nil, err
	}

	token = c.newToken(EdDSA, encoding.EncodedLen(ed25519.SignatureSize))
	sig := ed25519.Sign(key, token)

	i := len(token)
	token = token[:cap(token)]
	token[i] = '.'

	encoding.Encode(token[i+1:], sig)

	return token, nil
}

// HMACSign updates the Raw field and returns a new JWT.
// The return is an AlgError when alg is not in HMACAlgs.
func (c *Claims) HMACSign(alg string, secret []byte) (token []byte, err error) {
	if len(secret) == 0 {
		return nil, errNoSecret
	}

	if err := c.sync(); err != nil {
		return nil, err
	}

	hash, err := hashLookup(alg, HMACAlgs)
	if err != nil {
		return nil, err
	}
	digest := hmac.New(hash.New, secret)

	token = c.newToken(alg, encoding.EncodedLen(digest.Size()))
	digest.Write(token)
	token = append(token, '.')

	// use tail as a buffer; encoder won't overhaul source space
	bufOffset := cap(token) - digest.Size()
	encoding.Encode(token[len(token):cap(token)], digest.Sum(token[bufOffset:bufOffset]))

	return token[:cap(token)], nil
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

	token = c.newToken(alg, encoding.EncodedLen(key.Size()))
	digest.Write(token)

	// use signature space as a buffer while not set
	buf := token[len(token):]

	var sig []byte
	if alg[0] == 'P' {
		sig, err = rsa.SignPSS(rand.Reader, key, hash, digest.Sum(buf), nil)
	} else {
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, hash, digest.Sum(buf))
	}
	if err != nil {
		return nil, err
	}

	i := len(token)
	token = token[:cap(token)]
	token[i] = '.'
	encoding.Encode(token[i+1:], sig)

	return token, nil
}

// NewToken returns a new JWT with the signature bytes all zero.
func (c *Claims) newToken(alg string, encSigLen int) []byte {
	encHeader := c.formatHeader(alg)

	l := len(encHeader) + 1 + encoding.EncodedLen(len(c.Raw))
	token := make([]byte, l, l+1+encSigLen)

	i := copy(token, encHeader)
	token[i] = '.'
	i++
	encoding.Encode(token[i:], c.Raw)

	return token[:l]
}

// FormatHeader encodes the JOSE header.
func (c *Claims) formatHeader(alg string) string {
	if kid := c.KeyID; kid != "" {
		buf := make([]byte, 7, 19+len(kid)+len(alg))
		copy(buf, `{"alg":`)
		buf = strconv.AppendQuote(buf, alg)
		buf = append(buf, `,"kid":`...)
		buf = strconv.AppendQuote(buf, kid)
		buf = append(buf, '}')

		return encoding.EncodeToString(buf)
	}

	switch alg {
	case EdDSA:
		return "eyJhbGciOiJFZERTQSJ9"
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
		buf := make([]byte, 7, 10+len(alg))
		copy(buf, `{"alg":`)
		buf = strconv.AppendQuote(buf, alg)
		buf = append(buf, '}')

		return encoding.EncodeToString(buf)
	}
}
