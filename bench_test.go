package jwt

import (
	"crypto/rsa"
	"testing"
	"time"
)

var benchClaims = &Claims{
	Registered: Registered{
		Expires:  NewNumericTime(time.Now()),
		Audience: "benchmark",
	},
}

func BenchmarkHMACSign(b *testing.B) {
	// 512-bit key
	secret := make([]byte, 64)

	for alg := range HMACAlgs {
		b.Run(alg, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := benchClaims.HMACSign(alg, secret)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkHMACCheck(b *testing.B) {
	// 512-bit key
	secret := make([]byte, 64)

	variants := make(map[string][]byte, len(HMACAlgs))
	for alg := range HMACAlgs {
		token, err := benchClaims.HMACSign(alg, secret)
		if err != nil {
			b.Fatal(err)
		}
		variants[alg] = token
	}

	b.ResetTimer()

	for alg, token := range variants {
		b.Run(alg, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := HMACCheck(token, secret)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRSASign(b *testing.B) {
	variants := map[string]*rsa.PrivateKey{
		"1024-bit": testKeyRSA1024,
		"2048-bit": testKeyRSA2048,
		"4096-bit": testKeyRSA4096,
	}

	for name, key := range variants {
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := benchClaims.RSASign(RS384, key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRSACheck(b *testing.B) {
	variants := map[string]*rsa.PrivateKey{
		"1024-bit": testKeyRSA1024,
		"2048-bit": testKeyRSA2048,
		"4096-bit": testKeyRSA4096,
	}
	tokens := make(map[string][]byte, len(variants))
	for name, key := range variants {
		token, err := benchClaims.RSASign(RS384, key)
		if err != nil {
			b.Fatal(err)
		}
		tokens[name] = token
	}

	b.ResetTimer()

	for name, key := range variants {
		b.Run(name, func(b *testing.B) {
			token := tokens[name]
			for i := 0; i < b.N; i++ {
				_, err := RSACheck(token, &key.PublicKey)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
