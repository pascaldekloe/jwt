package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
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
	ECDSAs  []*ecdsa.PublicKey  // ECDSA credentials
	EdDSAs  []ed25519.PublicKey // EdDSA credentials
	RSAs    []*rsa.PublicKey    // RSA credentials
	Secrets [][]byte            // HMAC credentials

	// Optional key identification.
	// See Claims.KeyID for details.
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
