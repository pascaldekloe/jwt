package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strconv"
)

// HMACSign calls Sync and returns a new token serial.
func (c *Claims) HMACSign(alg string, secret []byte) (jwt []byte, err error) {
	if err := c.Sync(); err != nil {
		return nil, err
	}

	header, hash, err := headerWithHash(alg, HMACAlgs)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(hash.New, secret)

	encSigLen := encoding.EncodedLen(mac.Size())
	jwt = make([]byte, len(header)+encoding.EncodedLen(len(c.Raw))+encSigLen+2)

	// append header + body
	offset := copy(jwt, header)
	jwt[offset] = '.'
	offset++
	encoding.Encode(jwt[offset:], c.Raw)
	offset = len(jwt) - encSigLen - 1

	mac.Write(jwt[:offset])

	// append signature
	jwt[offset] = '.'
	offset++
	encoding.Encode(jwt[offset:], mac.Sum(nil))

	return jwt, nil
}

// RSASign calls Sync and returns a new token serial.
func (c *Claims) RSASign(alg string, key *rsa.PrivateKey) (jwt []byte, err error) {
	if err := c.Sync(); err != nil {
		return nil, err
	}

	header, hash, err := headerWithHash(alg, RSAAlgs)
	if err != nil {
		return nil, err
	}

	encSigLen := encoding.EncodedLen((key.N.BitLen() + 7) / 8)
	jwt = make([]byte, len(header)+encoding.EncodedLen(len(c.Raw))+encSigLen+2)

	// append header + body
	offset := copy(jwt, header)
	jwt[offset] = '.'
	offset++
	encoding.Encode(jwt[offset:], c.Raw)
	offset = len(jwt) - encSigLen - 1

	h := hash.New()
	h.Write(jwt[:offset])
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, h.Sum(nil))
	if err != nil {
		return nil, errors.New("jwt: " + err.Error())
	}

	// append signature
	jwt[offset] = '.'
	offset++
	encoding.Encode(jwt[offset:], sig)

	return jwt, nil
}

var fixedHeaders = map[string]string{
	HS256: encoding.EncodeToString([]byte(`{"alg":"HS256"}`)),
	HS384: encoding.EncodeToString([]byte(`{"alg":"HS384"}`)),
	HS512: encoding.EncodeToString([]byte(`{"alg":"HS512"}`)),
	RS256: encoding.EncodeToString([]byte(`{"alg":"RS256"}`)),
	RS384: encoding.EncodeToString([]byte(`{"alg":"RS384"}`)),
	RS512: encoding.EncodeToString([]byte(`{"alg":"RS512"}`)),
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

	header, ok := fixedHeaders[alg]
	if !ok {
		buf := make([]byte, 10+len(alg))
		copy(buf, `{"alg":`)
		strconv.AppendQuote(buf[:7], alg)
		buf[len(buf)-1] = '}'
		header = encoding.EncodeToString(buf)
	}

	return header, hash, nil
}
