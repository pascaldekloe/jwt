package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/pascaldekloe/jwt"
)

var someECKey *ecdsa.PrivateKey

func init() {
	var err error
	someECKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
}

// Full access to the JWT claims.
func ExampleHandler_direct() {
	h := &jwt.Handler{
		Target: nil,
		Secret: []byte("killarcherdie"),

		// use as http.HandlerFunc with JWT argument
		Func: func(w http.ResponseWriter, req *http.Request, claims *jwt.Claims) (pass bool) {
			if n, ok := claims.Number("deadline"); !ok {
				fmt.Fprintln(w, "you don't have a deadline")
			} else {
				t := jwt.NumericTime(n)
				fmt.Fprintln(w, "deadline at", t.String())
			}
			return // false stops processing
		},
	}

	req := httptest.NewRequest("GET", "/status", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJkZWFkbGluZSI6NjcxNTAwNzk5fQ.yeUUNOj4-RvNp5Lt0d3lpS7MTgsS_Uk9XnsXJ3kVLhw")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	fmt.Printf("HTTP %d: %s", resp.Code, resp.Body)
	// output: HTTP 200: deadline at 1991-04-12T23:59:59Z
}

// Standard compliant security out-of-the-box.
func ExampleHandler_expiry() {
	h := &jwt.Handler{
		Target: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("reached target handler")
		}),

		ECDSAKey: &someECKey.PublicKey,

		Func: func(w http.ResponseWriter, req *http.Request, claims *jwt.Claims) (pass bool) {
			panic("reached JWT-enhanced handler")
		},
	}

	// request with expired token
	req := httptest.NewRequest("GET", "/had-something-for-this", nil)
	var c jwt.Claims
	c.Expires = jwt.NewNumericTime(time.Now().Add(-time.Second))
	if err := c.ECDSASignHeader(req, jwt.ES512, someECKey); err != nil {
		panic(err)
	}

	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	fmt.Println("HTTP", resp.Code)
	fmt.Println("WWW-Authenticate:", resp.Header().Get("WWW-Authenticate"))
	// output:
	// HTTP 401
	// WWW-Authenticate: Bearer error="invalid_token", error_description="jwt: time constraints exceeded"
}
