package jwt_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/pascaldekloe/jwt"
)

// JWTSecret is the HMAC key.
var JWTSecret = []byte("guest")

func Example() {
	// run secured service
	srv := httptest.NewTLSServer(&jwt.Handler{
		Target: http.HandlerFunc(Greeting),
		Secret: JWTSecret,
		HeaderBinding: map[string]string{
			"sub": "X-Verified-User", // registered [standard] claim name
			"fn":  "X-Verified-Name", // private [custom] claim name
		},
	})
	defer srv.Close()

	// build request with claims
	claims := &jwt.Claims{
		Registered: jwt.Registered{
			Subject: "lakane",
		},
		Set: map[string]interface{}{
			"fn": "Lana Anthony Kane",
		},
	}
	req, err := http.NewRequest("GET", srv.URL, nil)
	if err != nil {
		panic(err)
	}
	if err := claims.HMACSignHeader(req, jwt.HS512, JWTSecret); err != nil {
		panic(err)
	}

	// call service
	resp, err := srv.Client().Do(req)
	if err != nil {
		panic(err)
	}
	fmt.Println("HTTP", resp.Status)
	io.Copy(os.Stdout, resp.Body)
	// output: HTTP 200 OK
	// Hello Lana Anthony Kane!
	// You are authorized as lakane.
}

// Greeting is a standard HTTP handler fuction.
func Greeting(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Hello %s!\nYou are authorized as %s.\n",
		req.Header.Get("X-Verified-Name"), req.Header.Get("X-Verified-User"))
}
