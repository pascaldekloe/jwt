package jwt_test

import (
	"crypto"
	_ "crypto/md5" // link into binary
	"fmt"

	"github.com/pascaldekloe/jwt"
)

func init() {
	// additional algorithm registration
	jwt.HMACAlgs["MD5"] = crypto.MD5
}

// Non-Standard Algorithm Use
func Example_extend() {
	c := new(jwt.Claims)
	c.ID = "Me Too!"

	// issue with custom algorithm
	token, err := c.HMACSign("MD5", []byte("guest"))
	if err != nil {
		fmt.Println("sign error:", err)
		return
	}
	fmt.Println("token:", string(token))
	fmt.Println("header:", string(c.RawHeader))

	// verify custom algorithm
	got, err := jwt.HMACCheck(token, []byte("guest"))
	if err != nil {
		fmt.Println("check error:", err)
		return
	}
	fmt.Println("payload:", string(got.Raw))
	// Output:
	// token: eyJhbGciOiJNRDUifQ.eyJqdGkiOiJNZSBUb28hIn0.W5dsc6-lD0Bgc58TP_YOTg
	// header: {"alg":"MD5"}
	// payload: {"jti":"Me Too!"}
}
