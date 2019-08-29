// Package x provides experimental functionality.
package x

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/pascaldekloe/jwt"
)

var encoding = base64.RawURLEncoding

type jwk struct {
	Keys []*jwk

	Kty *string
	Crv string

	K, X, Y, N, E *string
}

// LoadJWK adds keys from a JWK or a JWK Set, and returns the count.
// Both private and public keys can be used.
func LoadJWK(keys *jwt.KeyRegister, data []byte) (n int, err error) {
	j := new(jwk)
	if err := json.Unmarshal(data, j); err != nil {
		return 0, err
	}

	if j.Keys == nil {
		// single key
		if err := addJWK(keys, j); err != nil {
			return 0, err
		}
		return 1, nil
	}

	// key set
	for i, k := range j.Keys {
		if err := addJWK(keys, k); err != nil {
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

func addJWK(keys *jwt.KeyRegister, j *jwk) error {
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
