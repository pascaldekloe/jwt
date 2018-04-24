package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"sync"
)

// HMACSign calls Sync and returns a new JWT.
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
func (c *Claims) RSASign(alg string, key *rsa.PrivateKey) (token []byte, err error) {
	if err := c.Sync(); err != nil {
		return nil, err
	}

	header, hash, err := headerWithHash(alg, RSAAlgs)
	if err != nil {
		return nil, err
	}

	encSigLen := encoding.EncodedLen((key.N.BitLen() + 7) / 8)
	token = make([]byte, len(header)+encoding.EncodedLen(len(c.Raw))+encSigLen+2)

	// append header + body
	offset := copy(token, header)
	token[offset] = '.'
	offset++
	encoding.Encode(token[offset:], c.Raw)
	offset = len(token) - encSigLen - 1

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

var headerCacheMutex sync.RWMutex
var headerCache = map[string]string{
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

	headerCacheMutex.RLock()
	header, ok := headerCache[alg]
	headerCacheMutex.RUnlock()

	if !ok {
		buf := make([]byte, 7, 10+len(alg))
		copy(buf, `{"alg":"`)
		buf = append(buf, alg...)
		buf = append(buf, '"', '}')
		header = encoding.EncodeToString(buf)

		headerCacheMutex.Lock()
		headerCache[alg] = header
		headerCacheMutex.Unlock()
	}

	return header, hash, nil
}
