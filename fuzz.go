//go:build gofuzz
// +build gofuzz

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"time"
)

// The function signature is defined by <github.com/dvyukov/go-fuzz>.
func FuzzCheck(data []byte) int {
	switch claims, err := ParseWithoutCheck(data); {
	case err == nil:
		claims.Valid(time.Date(2020, 3, 12, 16, 20, 36, 123456789, time.Local))

	case err == errPart,
		errors.As(err, new(base64.CorruptInputError)),
		errors.As(err, new(*json.SyntaxError)):
		// save CPU time
		log.Print("stop on ", err)
		return -1
	}

	var keys KeyRegister
	keys.Secrets = [][]byte{{'s', 'e', 'c', 'r', 'e', 't'}}
	_, err := keys.LoadPEM([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc5/E+krowgL6Q1Xv6g1Hrh74kccf
QdmMuEk/xPJQZD22ITRYiaCRaKFWaoDBcIv21JfJo2F4whHnOCFX0Y/ALg==
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAyyxC3Eb/7rf2mRwQ420k1UkOd8RRMbUi4hpgInj6mhw=
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANbwzDQGYgrbYNY8HLhnmB1SfGETROL2
OAbhk3Xu+bHsp+AO+FwC7hNjRGTGnvf3E/BmdGZWaXyKbR7Gj3MXg4UCAwEAAQ==
-----END PUBLIC KEY-----`), nil)
	if err != nil {
		log.Fatal("register initiation: ", err)
	}

	_, err = HMACCheck(data, keys.Secrets[0])
	if _, ok := err.(AlgError); ok {
		_, err = ECDSACheck(data, keys.ECDSAs[0])
	}
	if _, ok := err.(AlgError); ok {
		_, err = EdDSACheck(data, keys.EdDSAs[0])
	}
	if _, ok := err.(AlgError); ok {
		_, err = RSACheck(data, keys.RSAs[0])
	}

	_, regErr := keys.Check(data)
	switch {
	case err == nil && regErr == nil, err == ErrSigMiss && regErr == ErrSigMiss:
		return 1

	case err == nil, regErr == nil, err.Error() != regErr.Error():
		log.Fatalf("error inconsistency: plain checks got %q, while KeyRegister got %q", err, regErr)
	}

	return 0
}
