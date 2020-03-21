package jwt_test

import (
	"crypto"
	_ "crypto/md5" // link into binary
	"encoding/json"
	"fmt"

	"github.com/pascaldekloe/jwt"
)

func init() {
	// static algorithm registration
	jwt.HMACAlgs["MD5"] = crypto.MD5
}

// Non-Standard Algorithm & JOSE Heading
func Example_extend() {
	c := jwt.Claims{KeyID: "№4b"}
	token, err := c.HMACSign("MD5", []byte("guest"),
		json.RawMessage(`{"lan": "XL9", "tcode": 102}`))
	if err != nil {
		fmt.Println("sign error:", err)
		return
	}
	fmt.Println("token:", string(token))

	got, err := jwt.HMACCheck(token, []byte("guest"))
	if err != nil {
		fmt.Println("check error:", err)
		return
	}
	fmt.Println("header:", string(got.RawHeader))
	// Output:
	// token: eyJhbGciOiJNRDUiLCJraWQiOiLihJY0YiIsImxhbiI6IlhMOSIsInRjb2RlIjoxMDJ9.e30.Gfpw0GU5qxm8oNQZeYHhnQ
	// header: {"alg":"MD5","kid":"№4b","lan":"XL9","tcode":102}
}
