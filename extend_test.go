package jwt_test

import (
	"crypto"
	_ "crypto/md5" // link into binary
	"encoding/json"
	"fmt"

	"github.com/pascaldekloe/jwt"
)

// JWTHeaders defines custom JOSE heading for token production.
var JWTHeaders = json.RawMessage(`{"lan": "XL9", "tcode": 102}`)

func init() {
	// static algorithm registration
	jwt.HMACAlgs["HM5"] = crypto.MD5
}

// Demo use of a non-standard algorithm and custom JOSE heading.
func Example_extend() {
	// issue a JWT
	c := jwt.Claims{KeyID: "№1"}
	token, err := c.HMACSign("HM5", []byte("guest"), JWTHeaders)
	if err != nil {
		fmt.Println("sign error:", err)
		return
	}
	fmt.Println("token:", string(token))

	// verify a JWT
	claims, err := jwt.HMACCheck(token, []byte("guest"))
	if err != nil {
		fmt.Println("check error:", err)
		return
	}
	fmt.Println("header:", string(claims.RawHeader))
	// Output:
	// token: eyJhbGciOiJITTUiLCJraWQiOiLihJYxIiwibGFuIjoiWEw5IiwidGNvZGUiOjEwMn0.e30.8i8eLO5fHTv1ucdUWtBRMA
	// header: {"alg":"HM5","kid":"№1","lan":"XL9","tcode":102}
}
