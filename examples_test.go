package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/pascaldekloe/jwt"
)

var (
	PrivateECKey  *ecdsa.PrivateKey
	PublicECKey   *ecdsa.PublicKey
	PrivateEdKey  ed25519.PrivateKey
	PublicEdKey   ed25519.PublicKey
	PrivateRSAKey *rsa.PrivateKey
	PublicRSAKey  *rsa.PublicKey
)

func init() {
	var err error
	PrivateECKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	PublicECKey = &PrivateECKey.PublicKey

	PublicEdKey, PrivateEdKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	PrivateRSAKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	PublicRSAKey = &PrivateRSAKey.PublicKey
}

// Issue and validate a token with extra JOSE heading and non-standard claims.
// Note how the token is flawed due to absense of a purpose classification. The
// bare minimum should include time constraints.
func Example() {
	// Approval is a custom (a.k.a. private) claim element.
	type Approval struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	// ApprovalHeader classifies the JWT content.
	var ApprovalHeader = json.RawMessage(`{"lan": "XL9", "tcode": 102}`)
	// Secret4b is the symmetric key.
	var Secret4b = []byte("084e0343a0486ff05530df6c705c8bb4")

	// issue a JWT
	var c jwt.Claims
	c.Issuer = "malory"
	c.Subject = "sterling"
	c.Audiences = []string{"armory"}
	c.Set = map[string]interface{}{
		"approved": []Approval{{Name: "RPG-7", Count: 1}},
	}
	c.KeyID = "№4b"
	token, err := c.HMACSign(jwt.HS256, Secret4b, ApprovalHeader)
	if err != nil {
		fmt.Println("token creation failed on", err)
		return
	}
	fmt.Println("token:", string(token))

	// verify a JWT
	claims, err := jwt.HMACCheck(token, Secret4b)
	if err != nil {
		fmt.Println("credentials denied:", err)
		return
	}
	if !claims.Valid(time.Now()) {
		fmt.Println("credential time constraints exceeded")
		return
	}
	if !claims.AcceptAudience("armory") {
		fmt.Println("token reject on audience", claims.Audiences)
		return
	}
	fmt.Println("payload:", string(claims.Raw))
	// Output:
	// token: eyJhbGciOiJIUzI1NiIsImtpZCI6IuKEljRiIiwibGFuIjoiWEw5IiwidGNvZGUiOjEwMn0.eyJhcHByb3ZlZCI6W3sibmFtZSI6IlJQRy03IiwiY291bnQiOjF9XSwiYXVkIjpbImFybW9yeSJdLCJpc3MiOiJtYWxvcnkiLCJzdWIiOiJzdGVybGluZyJ9.hySn7b0UF2-8XNO63ChCc8s1PkO7NNIxtWR8VFjb4eE
	// payload: {"approved":[{"name":"RPG-7","count":1}],"aud":["armory"],"iss":"malory","sub":"sterling"}
}

// Standard HTTP Library Integration
func Example_http() {
	// standard HTTP handler
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello %s!\n", req.Header.Get("X-Verified-Name"))
		fmt.Fprintf(w, "You are authorized as %s.\n", req.Header.Get("X-Verified-User"))
	})

	// secure service configuration
	srv := httptest.NewTLSServer(&jwt.Handler{
		Target: http.DefaultServeMux,
		Keys:   &jwt.KeyRegister{EdDSAs: []ed25519.PublicKey{PublicEdKey}},

		HeaderPrefix: "X-Verified-",
		HeaderBinding: map[string]string{
			"sub": "X-Verified-User", // registered [standard] claim name
			"fn":  "X-Verified-Name", // private [custom] claim name
		},
	})
	defer srv.Close()

	// self-signed request
	req, _ := http.NewRequest("GET", srv.URL, nil)
	var claims jwt.Claims
	claims.Subject = "lakane"
	claims.Set = map[string]interface{}{
		"fn": "Lana Anthony Kane",
	}
	if err := claims.EdDSASignHeader(req, PrivateEdKey); err != nil {
		fmt.Println("sign error:", err)
	}

	// call service
	resp, _ := srv.Client().Do(req)
	fmt.Println("HTTP", resp.Status)
	io.Copy(os.Stdout, resp.Body)
	// Output:
	// HTTP 200 OK
	// Hello Lana Anthony Kane!
	// You are authorized as lakane.
}

// Typed Claim Lookups
func ExampleClaims_byName() {
	offset := time.Unix(1537622794, 0)
	c := jwt.Claims{
		Registered: jwt.Registered{
			Issuer:    "a",
			Subject:   "b",
			Audiences: []string{"c"},
			Expires:   jwt.NewNumericTime(offset.Add(time.Minute)),
			NotBefore: jwt.NewNumericTime(offset.Add(-time.Second)),
			Issued:    jwt.NewNumericTime(offset),
			ID:        "d",
		},
	}

	for _, name := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"} {
		if s, ok := c.String(name); ok {
			fmt.Printf("%q: %q\n", name, s)
		}
		if n, ok := c.Number(name); ok {
			fmt.Printf("%q: %0.f\n", name, n)
		}
	}
	// Output:
	// "iss": "a"
	// "sub": "b"
	// "aud": "c"
	// "exp": 1537622854
	// "nbf": 1537622793
	// "iat": 1537622794
	// "jti": "d"
}

// Claims Access From Request Context
func ExampleHandler_context() {
	h := &jwt.Handler{
		Target: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			claims := req.Context().Value("verified-jwt").(*jwt.Claims)
			if n, ok := claims.Number("deadline"); !ok {
				fmt.Fprintln(w, "no deadline")
			} else {
				fmt.Fprintln(w, "deadline at", (*jwt.NumericTime)(&n))
			}
		}),
		Keys:       &jwt.KeyRegister{Secrets: [][]byte{[]byte("killarcherdie")}},
		ContextKey: "verified-jwt",
	}

	// build request
	req := httptest.NewRequest("GET", "/status", nil)
	c := &jwt.Claims{
		Set: map[string]interface{}{
			"deadline": time.Date(1991, 4, 12, 23, 59, 59, 0, time.UTC).Unix(),
		},
	}
	if err := c.HMACSignHeader(req, jwt.HS384, []byte("killarcherdie")); err != nil {
		fmt.Println("sign error:", err)
	}

	// get response
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	fmt.Println("HTTP", resp.Code)
	fmt.Println(resp.Body)
	// Output:
	// HTTP 200
	// deadline at 1991-04-12T23:59:59Z
}

// Custom Response Format
func ExampleHandler_error() {
	h := &jwt.Handler{
		Target: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "My plan is to crowdsource a plan!")
		}),
		Keys: &jwt.KeyRegister{ECDSAs: []*ecdsa.PublicKey{PublicECKey}},
		Error: func(w http.ResponseWriter, error string, statusCode int) {
			// JSON messages instead of plain text
			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			w.WriteHeader(statusCode)
			fmt.Fprintf(w, `{"msg": %q}`, error)
		},
	}

	// build request
	req := httptest.NewRequest("GET", "/had-something-for-this", nil)
	var c jwt.Claims
	c.Expires = jwt.NewNumericTime(time.Now().Add(-time.Second))
	if err := c.ECDSASignHeader(req, jwt.ES512, PrivateECKey); err != nil {
		fmt.Println("sign error:", err)
	}

	// get response
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	fmt.Println("HTTP", resp.Code)
	fmt.Println(resp.Header().Get("WWW-Authenticate"))
	fmt.Println(resp.Body)
	// Output:
	// HTTP 401
	// Bearer error="invalid_token", error_description="jwt: time constraints exceeded"
	// {"msg": "jwt: time constraints exceeded"}
}

// Func As A Request Filter
func ExampleHandler_filter() {
	h := &jwt.Handler{
		Target: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "Elaborate voicemail hoax!")
		}),
		Keys: &jwt.KeyRegister{RSAs: []*rsa.PublicKey{PublicRSAKey}},
		Func: func(w http.ResponseWriter, req *http.Request, claims *jwt.Claims) (pass bool) {
			if claims.Subject != "marcher" {
				http.Error(w, "Ring, ring!", http.StatusServiceUnavailable)
				return false
			}

			return true
		},
	}

	// build request
	req := httptest.NewRequest("GET", "/urgent", nil)
	if err := new(jwt.Claims).RSASignHeader(req, jwt.PS512, PrivateRSAKey); err != nil {
		fmt.Println("sign error:", err)
	}

	// get response
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	fmt.Println("HTTP", resp.Code)
	fmt.Println(resp.Body)
	// Output:
	// HTTP 503
	// Ring, ring!
}

// PEM With Password Protection
func ExampleKeyRegister_LoadPEM_encrypted() {
	const pem = `Keep it private! ✨

-----BEGIN RSA PRIVATE KEY-----
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

	var keys jwt.KeyRegister
	n, err := keys.LoadPEM([]byte(pem), []byte("dangerzone"))
	if err != nil {
		fmt.Println("load error:", err)
	}
	fmt.Println(n, "keys added")
	// Output: 1 keys added
}

// JWKS With Key IDs
func ExampleKeyRegister_LoadJWK() {
	const json = `{
  "keys": [
    {"kty": "OKP", "crv":"Ed25519", "kid": "kazak",
      "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
      "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
    {"kty":"oct", "k":"a29mdGE", "kid": "good old"}
  ]
}`

	var keys jwt.KeyRegister
	n, err := keys.LoadJWK([]byte(json))
	if err != nil {
		fmt.Println("load error:", err)
	}
	fmt.Printf("%d keys added: ", n)
	fmt.Printf("EdDSA %q & ", keys.EdDSAIDs)
	fmt.Printf("secret %q: %q", keys.SecretIDs, keys.Secrets)
	// Output:
	// 2 keys added: EdDSA ["kazak"] & secret ["good old"]: ["kofta"]
}
