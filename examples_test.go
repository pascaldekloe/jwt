package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/pascaldekloe/jwt"
)

var someECKey *ecdsa.PrivateKey
var someRSAKey *rsa.PrivateKey

func init() {
	var err error
	someECKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	someRSAKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
}

// Happy path for standard HTTP handler fuction security.
func Example() {
	// run secured service
	srv := httptest.NewTLSServer(&jwt.Handler{
		Target: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			fmt.Fprintf(w, "Hello %s!\n", req.Header.Get("X-Verified-Name"))
			fmt.Fprintf(w, "You are authorized as %s.\n", req.Header.Get("X-Verified-User"))
		}),
		RSAKey: &someRSAKey.PublicKey,
		HeaderBinding: map[string]string{
			"sub": "X-Verified-User", // registered [standard] claim name
			"fn":  "X-Verified-Name", // private [custom] claim name
		},
	})
	defer srv.Close()

	// build request with claims
	req, _ := http.NewRequest("GET", srv.URL, nil)
	var claims jwt.Claims
	claims.Subject = "lakane"
	claims.Set = map[string]interface{}{
		"fn": "Lana Anthony Kane",
	}
	if err := claims.RSASignHeader(req, jwt.RS512, someRSAKey); err != nil {
		fmt.Println("sign error:", err)
	}

	// call service
	resp, _ := srv.Client().Do(req)
	fmt.Println("HTTP", resp.Status)
	io.Copy(os.Stdout, resp.Body)

	//output: HTTP 200 OK
	// Hello Lana Anthony Kane!
	// You are authorized as lakane.
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

	//output: HTTP 200: deadline at 1991-04-12T23:59:59Z
}

// Standard compliant security out-of-the-box.
func ExampleHandler_deny() {
	h := &jwt.Handler{
		Target: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("reached target handler")
		}),

		ECDSAKey: &someECKey.PublicKey,

		Func: func(w http.ResponseWriter, req *http.Request, claims *jwt.Claims) (pass bool) {
			panic("reached JWT-enhanced handler")
		},
	}

	req := httptest.NewRequest("GET", "/had-something-for-this", nil)
	doReq := func() {
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		fmt.Printf("HTTP %d %s\n", resp.Code, resp.Header().Get("WWW-Authenticate"))
	}

	// request with no authorization
	doReq()

	// request with disabled algorithm
	var c jwt.Claims
	if err := c.HMACSignHeader(req, jwt.HS512, []byte("guest")); err != nil {
		fmt.Println(err)
	}
	doReq()

	// request with expired token
	c.Expires = jwt.NewNumericTime(time.Now().Add(-time.Second))
	if err := c.ECDSASignHeader(req, jwt.ES512, someECKey); err != nil {
		fmt.Println(err)
	}
	doReq()

	//output:
	// HTTP 401 Bearer
	// HTTP 401 Bearer error="invalid_token", error_description="jwt: algorithm unknown"
	// HTTP 401 Bearer error="invalid_token", error_description="jwt: time constraints exceeded"
}
