package jwt_test

import (
	"crypto"
	_ "crypto/sha1" // link into binary
	"fmt"

	"github.com/pascaldekloe/jwt"
)

// SHA1 Algorithm Extensions
const (
	HS1 = "HS1"
	RS1 = "RS1"
)

func init() {
	// static registration
	jwt.HMACAlgs[HS1] = crypto.SHA1
	jwt.RSAAlgs[RS1] = crypto.SHA1
}

func Example_extend() {
	c := new(jwt.Claims)
	c.ID = "Me Too!"

	// issue with custom algorithm
	token, err := c.HMACSign(HS1, []byte("guest"))
	if err != nil {
		fmt.Println("sign error:", err)
		return
	}
	fmt.Println("token:", string(token))

	// verify custom algorithm
	got, err := jwt.HMACCheck(token, []byte("guest"))
	if err != nil {
		fmt.Println("check error:", err)
		return
	}
	fmt.Println("JSON:", string(got.Raw))

	// Output:
	// token: eyJhbGciOiJIUzEifQ.eyJqdGkiOiJNZSBUb28hIn0.hHye7VnslIM4jO-MoBfggMe8MUQ
	// JSON: {"jti":"Me Too!"}
}
