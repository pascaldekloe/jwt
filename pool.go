package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// KeyPool contains a set of recognized credentials.
type KeyPool struct {
	ECDSAs  []*ecdsa.PublicKey // ECDSA credentials
	RSAs    []*rsa.PublicKey   // RSA credentials
	Secrets [][]byte           // HMAC credentials
}

// Check parses a JWT and returns the claims set if, and only if, the signature
// checks out. Note that this excludes unsecured JWTs [ErrUnsecured].
// See Valid to complete the verification.
func (p *KeyPool) Check(token []byte) (*Claims, error) {
	err := ErrAlgUnk
	var c *Claims

	for _, secret := range p.Secrets {
		c, err = HMACCheck(token, secret)
		if err == nil {
			return c, nil
		}
		if err == ErrAlgUnk {
			break
		}
		if err != ErrSigMiss {
			return nil, err
		}
	}
	if err == ErrSigMiss {
		return nil, err
	}

	for _, key := range p.RSAs {
		c, err = RSACheck(token, key)
		if err == nil {
			return c, nil
		}
		if err == ErrAlgUnk {
			break
		}
		if err != ErrSigMiss {
			return nil, err
		}
	}
	if err == ErrSigMiss {
		return nil, err
	}

	for _, key := range p.ECDSAs {
		c, err = ECDSACheck(token, key)
		if err == nil {
			return c, nil
		}
		if err == ErrAlgUnk {
			break
		}
		if err != ErrSigMiss {
			return nil, err
		}
	}
	return nil, err
}

var errUnencryptedPEM = errors.New("jwt: unencrypted PEM rejected due password expectation")

// LoadPEM adds the keys from PEM-encoded data to the pool and returns the
// count. PEM encryption is enforced for non-empty password values.
func (p *KeyPool) LoadPEM(data, password []byte) (n int, err error) {
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

		switch block.Type {
		case "PUBLIC KEY":
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return n, err
			}
			switch t := key.(type) {
			case *ecdsa.PublicKey:
				p.ECDSAs = append(p.ECDSAs, t)
			case *rsa.PublicKey:
				p.RSAs = append(p.RSAs, t)
			default:
				return n, fmt.Errorf("jwt: unsupported key type %T", t)
			}

		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return n, err
			}
			p.ECDSAs = append(p.ECDSAs, &key.PublicKey)

		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return n, err
			}
			p.RSAs = append(p.RSAs, &key.PublicKey)

		default:
			return n, fmt.Errorf("jwt: unknown PEM type %q", block.Type)
		}

		n++
	}
}
