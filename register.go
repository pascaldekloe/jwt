package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// KeyRegister is a collection of recognized credentials.
type KeyRegister struct {
	ECDSAs  []*ecdsa.PublicKey  // ECDSA credentials
	EdDSAs  []ed25519.PublicKey // EdDSA credentials
	RSAs    []*rsa.PublicKey    // RSA credentials
	HMACs   []*HMAC             // HMAC credentials
	Secrets [][]byte            // HMAC credentials

	// Optional key identification. See Claims.KeyID for details.
	// Non-empty strings match the respective key or secret by index.
	ECDSAIDs  []string // ECDSAs key ID mapping
	EdDSAIDs  []string // EdDSA key ID mapping
	RSAIDs    []string // RSAs key ID mapping
	HMACIDs   []string // HMACs key ID mapping
	SecretIDs []string // Secrets key ID mapping
}

// Check parses a JWT if, and only if, the signature checks out.
// Use Claims.Valid to complete the verification.
func (keys *KeyRegister) Check(token []byte) (*Claims, error) {
	var c Claims
	lastDot, sig, alg, err := c.scan(token)
	if err != nil {
		return nil, err
	}
	body := token[:lastDot]
	buf := sig[len(sig):]

	switch hashAlg, err := hashLookup(alg, HMACAlgs); err.(type) {
	case nil:
		hMACOptions := keys.HMACs
		if c.KeyID != "" {
			for i, kid := range keys.HMACIDs {
				if kid == c.KeyID && i < len(hMACOptions) {
					hMACOptions = hMACOptions[i : i+1]
					break
				}
			}
		}
		for _, h := range hMACOptions {
			if h.alg == alg {
				digest := h.digests.Get().(hash.Hash)
				digest.Reset()
				digest.Write(body)
				sum := digest.Sum(buf)
				h.digests.Put(digest)
				if hmac.Equal(sig, sum) {
					return &c, c.applyPayload()
				}
			}
		}

		keyOptions := keys.Secrets
		if c.KeyID != "" {
			for i, kid := range keys.SecretIDs {
				if kid == c.KeyID && i < len(keyOptions) {
					keyOptions = keyOptions[i : i+1]
					break
				}
			}
		}

		for _, secret := range keyOptions {
			digest := hmac.New(hashAlg.New, secret)
			digest.Write(body)
			if hmac.Equal(sig, digest.Sum(buf)) {
				return &c, c.applyPayload()
			}
		}
		return nil, ErrSigMiss

	case AlgError:
		break // next
	default:
		return nil, err
	}

	if alg == EdDSA {
		keyOptions := keys.EdDSAs
		if c.KeyID != "" {
			for i, kid := range keys.EdDSAIDs {
				if kid == c.KeyID && i < len(keyOptions) {
					keyOptions = keyOptions[i : i+1]
					break
				}
			}
		}

		for _, key := range keyOptions {
			if ed25519.Verify(key, body, sig) {
				return &c, c.applyPayload()
			}
		}
		return nil, ErrSigMiss
	}

	switch hash, err := hashLookup(alg, RSAAlgs); err.(type) {
	case nil:
		keyOptions := keys.RSAs
		if c.KeyID != "" {
			for i, kid := range keys.RSAIDs {
				if kid == c.KeyID && i < len(keyOptions) {
					keyOptions = keyOptions[i : i+1]
					break
				}
			}
		}

		digest := hash.New()
		digest.Write(body)
		digestSum := digest.Sum(buf)
		for _, key := range keyOptions {
			if alg != "" && alg[0] == 'P' {
				err = rsa.VerifyPSS(key, hash, digestSum, sig, &pSSOptions)
			} else {
				err = rsa.VerifyPKCS1v15(key, hash, digestSum, sig)
			}
			if err == nil {
				return &c, c.applyPayload()
			}
		}
		return nil, ErrSigMiss

	case AlgError:
		break // next
	default:
		return nil, err
	}

	switch hash, err := hashLookup(alg, ECDSAAlgs); err {
	case nil:
		keyOptions := keys.ECDSAs
		if c.KeyID != "" {
			for i, kid := range keys.ECDSAIDs {
				if kid == c.KeyID && i < len(keyOptions) {
					keyOptions = keyOptions[i : i+1]
					break
				}
			}
		}

		r := new(big.Int).SetBytes(sig[:len(sig)/2])
		s := new(big.Int).SetBytes(sig[len(sig)/2:])
		digest := hash.New()
		digest.Write(body)
		digestSum := digest.Sum(buf)
		for _, key := range keyOptions {
			if ecdsa.Verify(key, digestSum, r, s) {
				return &c, c.applyPayload()
			}
		}
		return nil, ErrSigMiss

	default:
		return nil, err
	}
}

var errUnencryptedPEM = errors.New("jwt: unencrypted PEM rejected due password expectation")

// LoadPEM scans text for PEM-encoded keys. Each occurrence found is then added
// to the register. Extraction works with certificates, public keys and private
// keys. PEM encryption is enforced with a non-empty password to ensure security
// when ordered.
func (keys *KeyRegister) LoadPEM(text, password []byte) (keysAdded int, err error) {
	for {
		block, remainder := pem.Decode(text)
		if block == nil {
			return
		}
		text = remainder

		if x509.IsEncryptedPEMBlock(block) {
			block.Bytes, err = x509.DecryptPEMBlock(block, password)
			if err != nil {
				return keysAdded, err
			}
		} else if len(password) != 0 {
			return keysAdded, errUnencryptedPEM
		}

		var key interface{}
		var err error

		// See RFC 7468, section 4.
		switch block.Type {
		case "CERTIFICATE":
			certs, err := x509.ParseCertificates(block.Bytes)
			if err != nil {
				return keysAdded, err
			}
			for _, c := range certs {
				if err := keys.add(c.PublicKey, ""); err != nil {
					return keysAdded, err
				}
				keysAdded++
			}
			continue

		case "PUBLIC KEY":
			key, err = x509.ParsePKIXPublicKey(block.Bytes)

		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)

		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)

		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)

		default:
			return keysAdded, fmt.Errorf("jwt: unknown PEM type %q", block.Type)
		}
		if err != nil {
			return keysAdded, err
		}
		if err := keys.add(key, ""); err != nil {
			return keysAdded, err
		}

		keysAdded++
	}
}

func (keys *KeyRegister) add(key interface{}, kid string) error {
	var i int
	var ids *[]string

	switch t := key.(type) {
	case *ecdsa.PublicKey:
		i = len(keys.ECDSAs)
		keys.ECDSAs = append(keys.ECDSAs, t)
		ids = &keys.ECDSAIDs
	case *ecdsa.PrivateKey:
		i = len(keys.ECDSAs)
		keys.ECDSAs = append(keys.ECDSAs, &t.PublicKey)
		ids = &keys.ECDSAIDs
	case ed25519.PublicKey:
		i = len(keys.EdDSAs)
		keys.EdDSAs = append(keys.EdDSAs, t)
		ids = &keys.EdDSAIDs
	case ed25519.PrivateKey:
		i = len(keys.EdDSAs)
		keys.EdDSAs = append(keys.EdDSAs, t.Public().(ed25519.PublicKey))
		ids = &keys.EdDSAIDs
	case *rsa.PublicKey:
		i = len(keys.RSAs)
		keys.RSAs = append(keys.RSAs, t)
		ids = &keys.RSAIDs
	case *rsa.PrivateKey:
		i = len(keys.RSAs)
		keys.RSAs = append(keys.RSAs, &t.PublicKey)
		ids = &keys.RSAIDs
	case []byte:
		i = len(keys.Secrets)
		keys.Secrets = append(keys.Secrets, t)
		ids = &keys.SecretIDs
	default:
		return fmt.Errorf("jwt: unsupported key type %T", t)
	}

	if kid != "" {
		for len(*ids) <= i {
			*ids = append(*ids, "")
		}
		(*ids)[i] = kid
	}

	return nil
}

// PEM exports the (public) keys as PEM-encoded PKIX.
// Elements from the Secret field, if any, are not included.
func (keys *KeyRegister) PEM() ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, key := range keys.ECDSAs {
		if err := encodePEM(buf, key); err != nil {
			return nil, err
		}
	}
	for _, key := range keys.EdDSAs {
		// There is no error case for EdDSA at the moment.
		// Still want check for future stability.
		if err := encodePEM(buf, key); err != nil {
			return nil, err
		}
	}
	for _, key := range keys.RSAs {
		if err := encodePEM(buf, key); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func encodePEM(buf *bytes.Buffer, key interface{}) error {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	return pem.Encode(buf, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}

type jwk struct {
	Keys []*jwk

	Kid string
	Kty *string
	Crv string

	K, X, Y, N, E *string
}

// LoadJWK adds keys from the JSON data to the register, including the key ID,
// a.k.a "kid", when present. If the object has a "keys" attribute, then data is
// read as a JWKS (JSON Web Key Set). Otherwise, data is read as a single JWK.
func (keys *KeyRegister) LoadJWK(data []byte) (keysAdded int, err error) {
	j := new(jwk)
	if err := json.Unmarshal(data, j); err != nil {
		return 0, err
	}

	if j.Keys == nil {
		if err := keys.addJWK(j); err != nil {
			return 0, err
		}
		return 1, nil
	}

	for i, k := range j.Keys {
		if err := keys.addJWK(k); err != nil {
			return i, err
		}
	}
	return len(j.Keys), nil
}

var (
	errJWKNoKty = errors.New("jwt: JWK missing \"kty\" field")
	errJWKParam = errors.New("jwt: JWK missing key–parameter field")

	errJWKCurveSize = errors.New("jwt: JWK curve parameters don't match curve size")
	errJWKCurveMiss = errors.New("jwt: JWK curve parameters are not on the curve")
)

func (keys *KeyRegister) addJWK(j *jwk) error {
	// See RFC 7518, subsection 6.1

	if j.Kty == nil {
		return errJWKNoKty
	}
	switch *j.Kty {
	default:
		return fmt.Errorf("jwt: JWK with unsupported key type %q", *j.Kty)

	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return fmt.Errorf("jwt: JWK with unsupported elliptic curve %q", j.Crv)
		}

		x, err := intParam(j.X)
		if err != nil {
			return err
		}
		y, err := intParam(j.Y)
		if err != nil {
			return err
		}

		size := (curve.Params().BitSize + 7) / 8
		xSize, ySize := (x.BitLen()+7)/8, (y.BitLen()+7)/8
		if xSize != size || ySize != size {
			return errJWKCurveSize
		}

		if !curve.IsOnCurve(x, y) {
			return errJWKCurveMiss
		}

		keys.add(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, j.Kid)

	case "RSA":
		n, err := intParam(j.N)
		if err != nil {
			return err
		}
		e, err := intParam(j.E)
		if err != nil {
			return err
		}

		keys.add(&rsa.PublicKey{N: n, E: int(e.Int64())}, j.Kid)

	case "oct":
		bytes, err := dataParam(j.K)
		if err != nil {
			return err
		}
		keys.add(bytes, j.Kid)

	case "OKP":
		switch j.Crv {
		case "Ed25519":
			bytes, err := dataParam(j.X)
			if err != nil {
				return err
			}
			keys.add(ed25519.PublicKey(bytes), j.Kid)
		default:
			return fmt.Errorf("jwt: JWK with unsupported elliptic curve %q", j.Crv)
		}
	}

	return nil
}

func dataParam(p *string) ([]byte, error) {
	if p == nil {
		return nil, errJWKParam
	}
	bytes, err := encoding.DecodeString(*p)
	if err != nil {
		return nil, fmt.Errorf("jwt: JWK with malformed key–parameter field: %w", err)
	}
	return bytes, nil
}

func intParam(p *string) (*big.Int, error) {
	bytes, err := dataParam(p)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(bytes), nil
}
