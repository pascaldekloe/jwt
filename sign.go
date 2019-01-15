package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"hash"
	"strconv"
)

// ECDSASign calls Sync and returns a new JWT.
// When the algorithm is not in ECDSAAlgs, then the error is ErrAlgUnk.
// The caller must use the correct key for the respective algorithm (P-256 for
// ES256, P-384 for ES384 and P-521 for ES512) or risk malformed token production.
func (c *Claims) ECDSASign(alg string, key *ecdsa.PrivateKey) (token []byte, err error) {
	if err := c.Sync(); err != nil {
		return nil, err
	}

	// signature contains pair (r, s) as per RFC 7518 section 3.4
	sig := make([]byte, 2*((key.Curve.Params().BitSize+7)/8))
	encSigLen := encoding.EncodedLen(len(sig))

	hash := ECDSAAlgs[alg]
	encHeader, err := c.formatHeader(alg, hash)
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
// When the algorithm is not in HMACAlgs, then the error is ErrAlgUnk.
func (c *Claims) HMACSign(alg string, secret []byte) (token []byte, err error) {
	if err := c.Sync(); err != nil {
		return nil, err
	}

	hash := HMACAlgs[alg]
	encHeader, err := c.formatHeader(alg, hash)
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
// When the algorithm is not in RSAAlgs, then the error is ErrAlgUnk.
func (c *Claims) RSASign(alg string, key *rsa.PrivateKey) (token []byte, err error) {
	if err := c.Sync(); err != nil {
		return nil, err
	}

	hash := RSAAlgs[alg]
	encHeader, err := c.formatHeader(alg, hash)
	if err != nil {
		return nil, err
	}
	digest := hash.New()
	encSigLen := encoding.EncodedLen(key.Size())
	token = c.newUnsignedToken(encHeader, encSigLen, digest)

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

// FormatHeader encodes the JOSE header and validates the hash.
func (c *Claims) formatHeader(alg string, hash crypto.Hash) (encHeader string, err error) {
	if hash == 0 {
		return "", ErrAlgUnk
	}
	if !hash.Available() {
		return "", errHashLink
	}

	if kid := c.KeyID; kid != "" {
		buf := make([]byte, 7, 24+len(kid))
		copy(buf, `{"alg":`)
		buf = strconv.AppendQuote(buf, alg)
		buf = append(buf, `,"kid":`...)
		buf = strconv.AppendQuote(buf, kid)
		buf = append(buf, '}')

		return encoding.EncodeToString(buf), nil
	}

	switch alg {
	case ES256:
		return "eyJhbGciOiJFUzI1NiJ9", nil
	case ES384:
		return "eyJhbGciOiJFUzM4NCJ9", nil
	case ES512:
		return "eyJhbGciOiJFUzUxMiJ9", nil
	case HS256:
		return "eyJhbGciOiJIUzI1NiJ9", nil
	case HS384:
		return "eyJhbGciOiJIUzM4NCJ9", nil
	case HS512:
		return "eyJhbGciOiJIUzUxMiJ9", nil
	case PS256:
		return "eyJhbGciOiJQUzI1NiJ9", nil
	case PS384:
		return "eyJhbGciOiJQUzM4NCJ9", nil
	case PS512:
		return "eyJhbGciOiJQUzUxMiJ9", nil
	case RS256:
		return "eyJhbGciOiJSUzI1NiJ9", nil
	case RS384:
		return "eyJhbGciOiJSUzM4NCJ9", nil
	case RS512:
		return "eyJhbGciOiJSUzUxMiJ9", nil
	default:
		buf := make([]byte, 7, 14)
		copy(buf, `{"alg":`)
		buf = strconv.AppendQuote(buf, alg)
		buf = append(buf, '}')

		return encoding.EncodeToString(buf), nil
	}
}
