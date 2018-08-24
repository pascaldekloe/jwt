package jwt

import (
	"crypto/rsa"
	"fmt"
	"sort"
	"testing"
	"time"
)

var benchClaims = &Claims{
	Registered: Registered{
		Expires:  NewNumericTime(time.Now()),
		Audience: "benchmark",
	},
}

func BenchmarkECDSASign(b *testing.B) {
	b.Run(ES256, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := benchClaims.ECDSASign(ES256, testKeyEC256)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run(ES384, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := benchClaims.ECDSASign(ES384, testKeyEC384)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run(ES512, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := benchClaims.ECDSASign(ES512, testKeyEC521)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkECDSACheck(b *testing.B) {
	b.Run(ES256, func(b *testing.B) {
		token, err := benchClaims.ECDSASign(ES256, testKeyEC256)
		if err != nil {
			b.Fatal(err)
		}
		for i := 0; i < b.N; i++ {
			_, err := ECDSACheck(token, &testKeyEC256.PublicKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run(ES384, func(b *testing.B) {
		token, err := benchClaims.ECDSASign(ES384, testKeyEC384)
		if err != nil {
			b.Fatal(err)
		}
		for i := 0; i < b.N; i++ {
			_, err := ECDSACheck(token, &testKeyEC384.PublicKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run(ES512, func(b *testing.B) {
		token, err := benchClaims.ECDSASign(ES512, testKeyEC521)
		if err != nil {
			b.Fatal(err)
		}
		for i := 0; i < b.N; i++ {
			_, err := ECDSACheck(token, &testKeyEC521.PublicKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkHMACSign(b *testing.B) {
	// 512-bit key
	secret := make([]byte, 64)

	// all supported algorithms in ascending order
	var algs []string
	for s := range HMACAlgs {
		algs = append(algs, s)
	}
	sort.Strings(algs)

	for _, alg := range algs {
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

	// all supported algorithms in ascending order
	var algs []string
	for s := range HMACAlgs {
		algs = append(algs, s)
	}
	sort.Strings(algs)

	// serial for each algorithm
	tokens := make([][]byte, len(algs))
	for i, alg := range algs {
		token, err := benchClaims.HMACSign(alg, secret)
		if err != nil {
			b.Fatal(err)
		}
		tokens[i] = token
	}

	b.ResetTimer()

	for i, alg := range algs {
		token := tokens[i]
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
	keys := []*rsa.PrivateKey{testKeyRSA1024, testKeyRSA2048, testKeyRSA4096}
	for _, key := range keys {
		size := ((key.N.BitLen() + 7) / 8) * 8
		b.Run(fmt.Sprintf("%d-bit", size), func(b *testing.B) {
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
	keys := []*rsa.PrivateKey{testKeyRSA1024, testKeyRSA2048, testKeyRSA4096}
	tokens := make([][]byte, len(keys))
	for i, key := range keys {
		token, err := benchClaims.RSASign(RS384, key)
		if err != nil {
			b.Fatal(err)
		}
		tokens[i] = token
	}

	b.ResetTimer()

	for i, key := range keys {
		token := tokens[i]
		size := ((key.N.BitLen() + 7) / 8) * 8
		b.Run(fmt.Sprintf("%d-bit", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := RSACheck(token, &key.PublicKey)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
