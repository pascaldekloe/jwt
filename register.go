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
	"math/big"
)

// KeyRegister contains recognized credentials.
type KeyRegister struct {
	ECDSAs  []*ecdsa.PublicKey  // ECDSA credentials
	EdDSAs  []ed25519.PublicKey // EdDSA credentials
	RSAs    []*rsa.PublicKey    // RSA credentials
	Secrets [][]byte            // HMAC credentials

	// Optional key identification. See Claims.KeyID for details.
	// Non-empty values match the respective keys (or secrets).
	ECDSAIDs  []string // ECDSAs key ID mapping
	EdDSAIDs  []string // EdDSA key ID mapping
	RSAIDs    []string // RSAs key ID mapping
	SecretIDs []string // Secrets key ID mapping
}

// Check parses a JWT if, and only if, the signature checks out.
// See Claims.Valid to complete the verification.
func (keys *KeyRegister) Check(token []byte) (*Claims, error) {
	firstDot, lastDot, sig, header, err := scan(token)
	if err != nil {
		return nil, err
	}

	if header.Alg == EdDSA {
		keyOptions := keys.EdDSAs
		if header.Kid != "" {
			for i, kid := range keys.EdDSAIDs {
				if kid == header.Kid && i < len(keyOptions) {
					keyOptions = keyOptions[i : i+1]
					break
				}
			}
		}

		for _, key := range keyOptions {
			if ed25519.Verify(key, token[:lastDot], sig) {
				return parseClaims(token[firstDot+1:lastDot], sig, header)
			}
		}
		return nil, ErrSigMiss
	}

	switch hash, err := hashLookup(header.Alg, HMACAlgs); err.(type) {
	case nil:
		keyOptions := keys.Secrets
		if header.Kid != "" {
			for i, kid := range keys.SecretIDs {
				if kid == header.Kid && i < len(keyOptions) {
					keyOptions = keyOptions[i : i+1]
					break
				}
			}
		}

		for _, secret := range keyOptions {
			digest := hmac.New(hash.New, secret)
			digest.Write(token[:lastDot])
			if hmac.Equal(sig, digest.Sum(sig[len(sig):])) {
				return parseClaims(token[firstDot+1:lastDot], sig, header)
			}
		}
		return nil, ErrSigMiss

	case AlgError:
		break // next
	default:
		return nil, err
	}

	switch hash, err := hashLookup(header.Alg, RSAAlgs); err.(type) {
	case nil:
		keyOptions := keys.RSAs
		if header.Kid != "" {
			for i, kid := range keys.RSAIDs {
				if kid == header.Kid && i < len(keyOptions) {
					keyOptions = keyOptions[i : i+1]
					break
				}
			}
		}

		digest := hash.New()
		digest.Write(token[:lastDot])
		digestSum := digest.Sum(sig[len(sig):])
		for _, key := range keyOptions {
			if header.Alg[0] == 'P' {
				err = rsa.VerifyPSS(key, hash, digestSum, sig, nil)
			} else {
				err = rsa.VerifyPKCS1v15(key, hash, digestSum, sig)
			}
			if err == nil {
				return parseClaims(token[firstDot+1:lastDot], sig, header)
			}
		}
		return nil, ErrSigMiss

	case AlgError:
		break // next
	default:
		return nil, err
	}

	switch hash, err := hashLookup(header.Alg, ECDSAAlgs); err {
	case nil:
		keyOptions := keys.ECDSAs
		if header.Kid != "" {
			for i, kid := range keys.ECDSAIDs {
				if kid == header.Kid && i < len(keyOptions) {
					keyOptions = keyOptions[i : i+1]
					break
				}
			}
		}

		r := big.NewInt(0).SetBytes(sig[:len(sig)/2])
		s := big.NewInt(0).SetBytes(sig[len(sig)/2:])
		digest := hash.New()
		digest.Write(token[:lastDot])
		digestSum := digest.Sum(sig[:0])
		for _, key := range keyOptions {
			if ecdsa.Verify(key, digestSum, r, s) {
				return parseClaims(token[firstDot+1:lastDot], sig, header)
			}
		}
		return nil, ErrSigMiss

	default:
		return nil, err
	}
}

var errUnencryptedPEM = errors.New("jwt: unencrypted PEM rejected due password expectation")

// LoadPEM adds keys from PEM-encoded data and returns the count. PEM encryption
// is enforced for non-empty password values. The source may be certificates,
// public keys, private keys, or a combination of any of the previous. Private
// keys are discared after the (automatic) public key extraction completes.
func (keys *KeyRegister) LoadPEM(data, password []byte) (n int, err error) {
	for {
		block, remainder := pem.Decode(data)
		if block == nil {
			return
		}
		data = remainder

		if x509.IsEncryptedPEMBlock(block) {
			block.Bytes, err = x509.DecryptPEMBlock(block, password)
			if err != nil {
				return
			}
		} else if len(password) != 0 {
			return n, errUnencryptedPEM
		}

		var key interface{}
		var err error

		// See RFC 7468, section 4.
		switch block.Type {
		case "CERTIFICATE":
			certs, err := x509.ParseCertificates(block.Bytes)
			if err != nil {
				return n, err
			}
			for _, c := range certs {
				if err := keys.add(c.PublicKey); err != nil {
					return n, err
				}
				n++
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
			return n, fmt.Errorf("jwt: unknown PEM type %q", block.Type)
		}
		if err != nil {
			return n, err
		}
		if err := keys.add(key); err != nil {
			return n, err
		}

		n++
	}
}

func (keys *KeyRegister) add(key interface{}) error {
	switch t := key.(type) {
	case *ecdsa.PublicKey:
		keys.ECDSAs = append(keys.ECDSAs, t)
	case *ecdsa.PrivateKey:
		keys.ECDSAs = append(keys.ECDSAs, &t.PublicKey)
	case ed25519.PublicKey:
		keys.EdDSAs = append(keys.EdDSAs, t)
	case ed25519.PrivateKey:
		keys.EdDSAs = append(keys.EdDSAs, t.Public().(ed25519.PublicKey))
	case *rsa.PublicKey:
		keys.RSAs = append(keys.RSAs, t)
	case *rsa.PrivateKey:
		keys.RSAs = append(keys.RSAs, &t.PublicKey)
	default:
		return fmt.Errorf("jwt: unsupported key type %T", t)
	}
	return nil
}

// PEM exports keys as PEM-encoded PKIX. An error is raised on .Secret entries.
func (keys *KeyRegister) PEM() ([]byte, error) {
	if len(keys.Secrets) != 0 {
		return nil, errors.New("jwt: won't encode secrets to PEM")
	}

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

	Kty *string
	Crv string

	K, X, Y, N, E *string
}

// LoadJWK adds keys from a JWK or a JWK Set, and returns the count.
// Both private and public keys can be used.
func (keys *KeyRegister) LoadJWK(data []byte) (n int, err error) {
	j := new(jwk)
	if err := json.Unmarshal(data, j); err != nil {
		return 0, err
	}

	if j.Keys == nil {
		// single key
		if err := keys.addJWK(j); err != nil {
			return 0, err
		}
		return 1, nil
	}

	// key set
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

		keys.ECDSAs = append(keys.ECDSAs, &ecdsa.PublicKey{Curve: curve, X: x, Y: y})

	case "RSA":
		n, err := intParam(j.N)
		if err != nil {
			return err
		}
		e, err := intParam(j.E)
		if err != nil {
			return err
		}

		keys.RSAs = append(keys.RSAs, &rsa.PublicKey{N: n, E: int(e.Int64())})

	case "oct":
		bytes, err := dataParam(j.K)
		if err != nil {
			return err
		}
		keys.Secrets = append(keys.Secrets, bytes)

	case "OKP":
		switch j.Crv {
		case "Ed25519":
			bytes, err := dataParam(j.X)
			if err != nil {
				return err
			}
			keys.EdDSAs = append(keys.EdDSAs, ed25519.PublicKey(bytes))
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
		return nil, fmt.Errorf("jwt: JWK with malformed key–parameter field: %s", err)
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
