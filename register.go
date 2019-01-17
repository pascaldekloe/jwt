package jwt

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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
func (keys *KeyRegister) Check(token []byte) (*Claims, error) {
	firstDot, lastDot, sig, header, err := scan(token)
	if err != nil {
		return nil, err
	}

	switch hash, err := header.match(HMACAlgs); err {
	case nil:
		for _, secret := range keys.Secrets {
			digest := hmac.New(hash.New, secret)
			digest.Write(token[:lastDot])
			if hmac.Equal(sig, digest.Sum(sig[len(sig):])) {
				return parseClaims(token[firstDot+1:lastDot], sig[:cap(sig)], header)
			}
		}
		return nil, ErrSigMiss

	case ErrAlgUnk:
		break // next
	default:
		return nil, err
	}

	switch hash, err := header.match(RSAAlgs); err {
	case nil:
		digest := hash.New()
		digest.Write(token[:lastDot])
		digestSum := digest.Sum(sig[len(sig):])
		for _, key := range keys.RSAs {
			if header.Alg[0] == 'P' {
				err = rsa.VerifyPSS(key, hash, digestSum, sig, nil)
			} else {
				err = rsa.VerifyPKCS1v15(key, hash, digestSum, sig)
			}
			if err == nil {
				return parseClaims(token[firstDot+1:lastDot], sig[:cap(sig)], header)
			}
		}
		return nil, ErrSigMiss

	case ErrAlgUnk:
		break // next
	default:
		return nil, err
	}

	switch hash, err := header.match(ECDSAAlgs); err {
	case nil:
		r := big.NewInt(0).SetBytes(sig[:len(sig)/2])
		s := big.NewInt(0).SetBytes(sig[len(sig)/2:])
		digest := hash.New()
		digest.Write(token[:lastDot])
		digestSum := digest.Sum(sig[:0])

		for _, key := range keys.ECDSAs {
			if ecdsa.Verify(key, digestSum, r, s) {
				return parseClaims(token[firstDot+1:lastDot], sig[:cap(sig)], header)
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
			}

		case "PUBLIC KEY":
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return n, err
			}
			if err := keys.add(key); err != nil {
				return n, err
			}

		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return n, err
			}
			keys.ECDSAs = append(keys.ECDSAs, &key.PublicKey)

		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return n, err
			}
			keys.RSAs = append(keys.RSAs, &key.PublicKey)

		default:
			return n, fmt.Errorf("jwt: unknown PEM type %q", block.Type)
		}

		n++
	}
}

func (keys *KeyRegister) add(key interface{}) error {
	switch t := key.(type) {
	case *ecdsa.PublicKey:
		keys.ECDSAs = append(keys.ECDSAs, t)
	case *rsa.PublicKey:
		keys.RSAs = append(keys.RSAs, t)
	default:
		return fmt.Errorf("jwt: unsupported key type %T", t)
	}
	return nil
}
