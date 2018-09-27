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

// PEM with password protection.
func ExampleKeyPool_LoadPEM_encrypted() {
	const key = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,65789712555A3E9FECD1D5E235B97B0C

o0Dz8S6QjGVq59yQdlakuKkoO0jKDN0PDu2L05ZLXwBQSGdIbRXtAOBRCNEME0V1
IF9pM6uRU7tqFoVneNTHD3XySJG8AHrTPSKC3Xw31pjEolMfoNDBAu1bYR6XxM2X
oDu2UNVB9vd/3b4bwTH9q5ISWdCVhS/ky0lC9lHXman/F/7MsemiVVCQ4XTIi9CR
nitMxJuXvkNBMtsyv+inmFMegKU6dj1DU93B9JpsFRRvy3TCfj9kRjhKWEpyindo
yaZMH3EGOA3ALW5kWyr+XegyYznQbVdDlo/ikO9BAywBOx+DdRG4xYxRdxYt8/HH
qXwPAGQe2veMlR7Iq3GjwHLebyuVc+iHbC7feRmNBpAT1RR7J+RIGlDPOBMUpuDT
A8HbNzPkoXPGh9vMsREXtR5aPCaZISdcm8DTlNiZCPaX5VHL4SRJ5XjI2rnahaOE
rhCFy0mxqQaKnEI9kCWWFmhX/MqzzfiW3yg0qFIAVLDQZZMFJr3jMHIvkxPk09rP
nQIjMRBalFXmSiksx8UEhAzyriqiXwwgEI0gJVHcs3EIQGD5jNqvIYTX67/rqSF2
OXoYuq0MHrAJgEfDncXvZFFMuAS/5KMvzSXfWr5/L0ncCU9UykjdPrFvetG/7IXQ
BT1TX4pOeW15a6fg6KwSZ5KPrt3o8qtRfW4Ov49hPD2EhnCTMbkCRBbW8F13+9YF
xzvC4Vm1r/Oa4TTUbf5tVto7ua/lZvwnu5DIWn2zy5ZUPrtn22r1ymVui7Iuhl0b
SRcADdHh3NgrjDjalhLDB95ho5omG39l7qBKBTlBAYJhDuAk9rIk1FCfCB8upztt
-----END RSA PRIVATE KEY-----`

	var p jwt.KeyPool
	n, err := p.LoadPEM([]byte(key), []byte("dangerzone"))
	if err != nil {
		fmt.Println("load error:", err)
	}
	fmt.Printf("got %d keys", n)
	//output: got 1 keys
}
