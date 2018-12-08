package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// KeyRegister contains recognized credentials.
type KeyRegister struct {
	ECDSAs  []*ecdsa.PublicKey // ECDSA credentials
	RSAs    []*rsa.PublicKey   // RSA credentials
	Secrets [][]byte           // HMAC credentials
}

// Check parses a JWT and returns the claims set if, and only if, the signature
// checks out. Note that this excludes unsecured JWTs [ErrUnsecured].
// See Claims.Valid to complete the verification.
func (r *KeyRegister) Check(token []byte) (*Claims, error) {
	err := ErrAlgUnk
	var c *Claims

	for _, secret := range r.Secrets {
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

	for _, key := range r.RSAs {
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

	for _, key := range r.ECDSAs {
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

// LoadPEM adds keys from PEM-encoded data and returns the count. PEM encryption
// is enforced for non-empty password values. The source may be certificates,
// public keys, private keys, or a combination of any of the previous. Private
// keys are discared after the (automatic) public key extraction completes.
func (r *KeyRegister) LoadPEM(data, password []byte) (n int, err error) {
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
		case "CERTIFICATE":
			certs, err := x509.ParseCertificates(block.Bytes)
			if err != nil {
				return n, err
			}
			for _, c := range certs {
				if err := r.add(c.PublicKey); err != nil {
					return n, err
				}
			}

		case "PUBLIC KEY":
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return n, err
			}
			if err := r.add(key); err != nil {
				return n, err
			}

		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return n, err
			}
			r.ECDSAs = append(r.ECDSAs, &key.PublicKey)

		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return n, err
			}
			r.RSAs = append(r.RSAs, &key.PublicKey)

		default:
			return n, fmt.Errorf("jwt: unknown PEM type %q", block.Type)
		}

		n++
	}
}

func (r *KeyRegister) add(key interface{}) error {
	switch t := key.(type) {
	case *ecdsa.PublicKey:
		r.ECDSAs = append(r.ECDSAs, t)
	case *rsa.PublicKey:
		r.RSAs = append(r.RSAs, t)
	default:
		return fmt.Errorf("jwt: unsupported key type %T", t)
	}
	return nil
}
