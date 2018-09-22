package jwt_test

import (
	"crypto"
	_ "crypto/sha1" // must link algorithm into binary
	"fmt"

	"github.com/pascaldekloe/jwt"
)

// HS1 is a SHA1 extension.
const HS1 = "HS1"

// Static algorithm registration.
func init() {
	jwt.HMACAlgs[HS1] = crypto.SHA1
}

// Use custom algorithm.
func Example_extend() {
	c := new(jwt.Claims)
	c.ID = "knockout gas"
	token, err := c.HMACSign(HS1, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("token=%s\n", token)

	got, err := jwt.HMACCheck(token, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("JSON=%s\n", got.Raw)

	// output:
	// token=eyJhbGciOiJIUzEifQ.eyJqdGkiOiJrbm9ja291dCBnYXMifQ.P6VjU3cwOfwyHuEB20DJyRCiv0A
	// JSON={"jti":"knockout gas"}
}
