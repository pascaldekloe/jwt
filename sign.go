package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strconv"
)

// FormatWithoutSign updates the Raw fields and returns a new JWT, with only the
// first two parts.
//
//	tokenWithoutSignature :≡ header-base64 '.' payload-base64
//	token                 :≡ tokenWithoutSignature '.' signature-base64
//
// The JOSE header (content) can be extended with extraHeaders, in the form of
// JSON objects. Redundant and/or duplicate keys are applied as provided.
func (c *Claims) FormatWithoutSign(alg string, extraHeaders ...json.RawMessage) (tokenWithoutSignature []byte, err error) {
	return c.newToken(alg, 0, extraHeaders)
}

// ECDSASign updates the Raw fields and returns a new JWT.
// The return is an AlgError when alg is not in ECDSAAlgs.
// The caller must use the correct key for the respective algorithm (P-256 for
// ES256, P-384 for ES384 and P-521 for ES512) or risk malformed token production.
//
// The JOSE header (content) can be extended with extraHeaders, in the form of
// JSON objects. Redundant and/or duplicate keys are applied as provided.
func (c *Claims) ECDSASign(alg string, key *ecdsa.PrivateKey, extraHeaders ...json.RawMessage) (token []byte, err error) {
	hash, err := hashLookup(alg, ECDSAAlgs)
	if err != nil {
		return nil, err
	}
	digest := hash.New()

	// signature contains pair (r, s) as per RFC 7518, subsection 3.4
	paramLen := (key.Curve.Params().BitSize + 7) / 8
	token, err = c.newToken(alg, encoding.EncodedLen(paramLen*2), extraHeaders)
	if err != nil {
		return nil, err
	}
	digest.Write(token)

	buf := token[len(token):]
	r, s, err := ecdsa.Sign(rand.Reader, key, digest.Sum(buf))
	if err != nil {
		return nil, err
	}

	token = append(token, '.')
	sig := token[len(token):cap(token)]
	// serialize r and s, using sig as a buffer
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

// EdDSASign updates the Raw fields and returns a new JWT.
//
// The JOSE header (content) can be extended with extraHeaders, in the form of
// JSON objects. Redundant and/or duplicate keys are applied as provided.
func (c *Claims) EdDSASign(key ed25519.PrivateKey, extraHeaders ...json.RawMessage) (token []byte, err error) {
	token, err = c.newToken(EdDSA, encoding.EncodedLen(ed25519.SignatureSize), extraHeaders)
	if err != nil {
		return nil, err
	}

	sig := ed25519.Sign(key, token)

	token = append(token, '.')
	encoding.Encode(token[len(token):cap(token)], sig)
	return token[:cap(token)], nil
}

// HMACSign updates the Raw fields and returns a new JWT.
// The return is an AlgError when alg is not in HMACAlgs.
//
// The JOSE header (content) can be extended with extraHeaders, in the form of
// JSON objects. Redundant and/or duplicate keys are applied as provided.
func (c *Claims) HMACSign(alg string, secret []byte, extraHeaders ...json.RawMessage) (token []byte, err error) {
	if len(secret) == 0 {
		return nil, errNoSecret
	}

	hash, err := hashLookup(alg, HMACAlgs)
	if err != nil {
		return nil, err
	}
	digest := hmac.New(hash.New, secret)

	token, err = c.newToken(alg, encoding.EncodedLen(digest.Size()), extraHeaders)
	if err != nil {
		return nil, err
	}
	digest.Write(token)

	token = append(token, '.')
	i := cap(token) - digest.Size()
	buf := token[i:i]
	encoding.Encode(token[len(token):cap(token)], digest.Sum(buf))
	return token[:cap(token)], nil
}

// Sign updates the Raw fields on c and returns a new JWT.
//
// The JOSE header (content) can be extended with extraHeaders, in the form of
// JSON objects. Redundant and/or duplicate keys are applied as provided.
func (h *HMAC) Sign(c *Claims, extraHeaders ...json.RawMessage) (token []byte, err error) {
	digest := h.digests.Get().(hash.Hash)
	defer h.digests.Put(digest)
	digest.Reset()

	token, err = c.newToken(h.alg, encoding.EncodedLen(digest.Size()), extraHeaders)
	if err != nil {
		return nil, err
	}
	digest.Write(token)

	token = append(token, '.')
	i := cap(token) - digest.Size()
	buf := token[i:i]
	encoding.Encode(token[len(token):cap(token)], digest.Sum(buf))
	return token[:cap(token)], nil
}

// RSASign updates the Raw fields and returns a new JWT.
// The return is an AlgError when alg is not in RSAAlgs.
//
// The JOSE header (content) can be extended with extraHeaders, in the form of
// JSON objects. Redundant and/or duplicate keys are applied as provided.
func (c *Claims) RSASign(alg string, key *rsa.PrivateKey, extraHeaders ...json.RawMessage) (token []byte, err error) {
	hash, err := hashLookup(alg, RSAAlgs)
	if err != nil {
		return nil, err
	}
	digest := hash.New()

	token, err = c.newToken(alg, encoding.EncodedLen(key.Size()), extraHeaders)
	if err != nil {
		return nil, err
	}
	digest.Write(token)

	var sig []byte
	buf := token[len(token):]
	if alg != "" && alg[0] == 'P' {
		sig, err = rsa.SignPSS(rand.Reader, key, hash, digest.Sum(buf), &pSSOptions)
	} else {
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, hash, digest.Sum(buf))
	}
	if err != nil {
		return nil, err
	}

	token = append(token, '.')
	encoding.Encode(token[len(token):cap(token)], sig)
	return token[:cap(token)], nil
}

var (
	headerES256 = []byte(`{"alg":"ES256"}`)
	headerES384 = []byte(`{"alg":"ES384"}`)
	headerES512 = []byte(`{"alg":"ES512"}`)
	headerEdDSA = []byte(`{"alg":"EdDSA"}`)
	headerHS256 = []byte(`{"alg":"HS256"}`)
	headerHS384 = []byte(`{"alg":"HS384"}`)
	headerHS512 = []byte(`{"alg":"HS512"}`)
	headerPS256 = []byte(`{"alg":"PS256"}`)
	headerPS384 = []byte(`{"alg":"PS384"}`)
	headerPS512 = []byte(`{"alg":"PS512"}`)
	headerRS256 = []byte(`{"alg":"RS256"}`)
	headerRS384 = []byte(`{"alg":"RS384"}`)
	headerRS512 = []byte(`{"alg":"RS512"}`)
)

func (c *Claims) newToken(alg string, encSigLen int, extraHeaders []json.RawMessage) ([]byte, error) {
	var payload interface{}
	if c.Set == nil {
		payload = &c.Registered
	} else {
		payload = c.Set

		// merge Registered
		if c.Issuer != "" {
			c.Set[issuer] = c.Issuer
		}
		if c.Subject != "" {
			c.Set[subject] = c.Subject
		}
		if len(c.Audiences) != 0 {
			array := make([]interface{}, len(c.Audiences))
			for i, s := range c.Audiences {
				array[i] = s
			}
			c.Set[audience] = array
		}
		if c.Expires != nil {
			c.Set[expires] = float64(*c.Expires)
		}
		if c.NotBefore != nil {
			c.Set[notBefore] = float64(*c.NotBefore)
		}
		if c.Issued != nil {
			c.Set[issued] = float64(*c.Issued)
		}
		if c.ID != "" {
			c.Set[id] = c.ID
		}
	}

	// define Claims.Raw
	if bytes, err := json.Marshal(payload); err != nil {
		return nil, err
	} else {
		c.Raw = json.RawMessage(bytes)
	}

	// try fixed JOSE header
	if len(extraHeaders) == 0 && c.KeyID == "" {
		var fixed string
		switch alg {
		case ES256:
			fixed = "eyJhbGciOiJFUzI1NiJ9."
			c.RawHeader = headerES256
		case ES384:
			fixed = "eyJhbGciOiJFUzM4NCJ9."
			c.RawHeader = headerES384
		case ES512:
			fixed = "eyJhbGciOiJFUzUxMiJ9."
			c.RawHeader = headerES512
		case EdDSA:
			fixed = "eyJhbGciOiJFZERTQSJ9."
			c.RawHeader = headerEdDSA
		case HS256:
			fixed = "eyJhbGciOiJIUzI1NiJ9."
			c.RawHeader = headerHS256
		case HS384:
			fixed = "eyJhbGciOiJIUzM4NCJ9."
			c.RawHeader = headerHS384
		case HS512:
			fixed = "eyJhbGciOiJIUzUxMiJ9."
			c.RawHeader = headerHS512
		case PS256:
			fixed = "eyJhbGciOiJQUzI1NiJ9."
			c.RawHeader = headerPS256
		case PS384:
			fixed = "eyJhbGciOiJQUzM4NCJ9."
			c.RawHeader = headerPS384
		case PS512:
			fixed = "eyJhbGciOiJQUzUxMiJ9."
			c.RawHeader = headerPS512
		case RS256:
			fixed = "eyJhbGciOiJSUzI1NiJ9."
			c.RawHeader = headerRS256
		case RS384:
			fixed = "eyJhbGciOiJSUzM4NCJ9."
			c.RawHeader = headerRS384
		case RS512:
			fixed = "eyJhbGciOiJSUzUxMiJ9."
			c.RawHeader = headerRS512
		}

		if fixed != "" {
			l := len(fixed) + encoding.EncodedLen(len(c.Raw))
			token := make([]byte, l, l+1+encSigLen)
			copy(token, fixed)
			encoding.Encode(token[len(fixed):], c.Raw)
			return token, nil
		}
	}

	// compose JOSE header
	var header bytes.Buffer
	if c.KeyID == "" {
		fmt.Fprintf(&header, `{"alg":%q}`, alg)
	} else {
		fmt.Fprintf(&header, `{"alg":%q,"kid":%q}`, alg, c.KeyID)
	}
	for _, raw := range extraHeaders {
		if len(raw) == 0 || raw[0] != '{' {
			return nil, errors.New("jwt: JOSE header addition is not a JSON object")
		}
		offset := header.Len() - 1
		header.Truncate(offset)
		if err := json.Compact(&header, []byte(raw)); err != nil {
			return nil, fmt.Errorf("jwt: malformed JOSE header addition: %w", err)
		}
		header.Bytes()[offset] = ','
	}
	c.RawHeader = json.RawMessage(header.Bytes())

	// compose token
	headerLen := encoding.EncodedLen(header.Len())
	l := headerLen + 1 + encoding.EncodedLen(len(c.Raw))
	token := make([]byte, l, l+1+encSigLen)
	encoding.Encode(token, header.Bytes())
	token[headerLen] = '.'
	encoding.Encode(token[headerLen+1:], c.Raw)
	return token, nil
}
