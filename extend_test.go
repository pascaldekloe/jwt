package jwt_test

import (
	"crypto"
	_ "crypto/sha1" // must link into binary
	"fmt"

	"github.com/pascaldekloe/jwt"
)

// HS1 is a SHA1 extension.
const HS1 = "HS1"

func init() {
	// static registration
	jwt.HMACAlgs[HS1] = crypto.SHA1
}

// Use custom algorithm.
func Example_extend() {
	c := new(jwt.Claims)
	c.ID = "Me Too!"

	// issue
	token, err := c.HMACSign(HS1, []byte("guest"))
	if err != nil {
		fmt.Println("sign error:", err)
	}
	fmt.Printf("token: %s\n", token)

	// verify
	got, err := jwt.HMACCheck(token, []byte("guest"))
	if err != nil {
		fmt.Println("check error:", err)
	}
	fmt.Printf("JSON: %s\n", got.Raw)

	// Output:
	// token: eyJhbGciOiJIUzEifQ.eyJqdGkiOiJNZSBUb28hIn0.hHye7VnslIM4jO-MoBfggMe8MUQ
	// JSON: {"jti":"Me Too!"}
}
