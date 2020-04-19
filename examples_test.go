package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/pascaldekloe/jwt"
)

var (
	ECPrivateKey  *ecdsa.PrivateKey
	ECPublicKey   *ecdsa.PublicKey
	EdPrivateKey  ed25519.PrivateKey
	EdPublicKey   ed25519.PublicKey
	RSAPrivateKey *rsa.PrivateKey
	RSAPublicKey  *rsa.PublicKey
)

func init() {
	r := rand.New(rand.NewSource(42))

	var err error
	ECPrivateKey, err = ecdsa.GenerateKey(elliptic.P521(), r)
	if err != nil {
		panic(err)
	}
	ECPublicKey = &ECPrivateKey.PublicKey

	EdPublicKey, EdPrivateKey, err = ed25519.GenerateKey(r)
	if err != nil {
		panic(err)
	}

	RSAPrivateKey, err = rsa.GenerateKey(r, 2048)
	if err != nil {
		panic(err)
	}
	RSAPublicKey = &RSAPrivateKey.PublicKey
}

// Note how the security is flawed without any purpose claims.
// The bare minimum should include time constraints.
func Example() {
	var c jwt.Claims
	c.Issuer = "malory"
	c.Subject = "sterling"
	c.Audiences = []string{"armory"}

	// Approval is a custom claim element.
	type Approval struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	c.Set = map[string]interface{}{
		"approved": []Approval{{"RPG-7", 1}},
	}

	// issue a JWT
	token, err := c.RSASign(jwt.RS256, RSAPrivateKey)
	if err != nil {
		fmt.Println("token creation failed on", err)
		return
	}

	// validate the JWT
	claims, err := jwt.RSACheck(token, RSAPublicKey)
	if err != nil {
		fmt.Println("credentials denied on", err)
		return
	}
	if !claims.Valid(time.Now()) {
		fmt.Println("time constraints exceeded")
		return
	}
	if !claims.AcceptAudience("armory") {
		fmt.Println("reject on audience", claims.Audiences)
		return
	}
	fmt.Println(string(claims.Raw))
	// Output:
	// {"approved":[{"name":"RPG-7","count":1}],"aud":["armory"],"iss":"malory","sub":"sterling"}
}

// Standard HTTP Library Integration
func Example_hTTP() {
	// standard HTTP handler
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello %s!\n", req.Header.Get("X-Verified-Name"))
		fmt.Fprintf(w, "You are authorized as %s.\n", req.Header.Get("X-Verified-User"))
	})

	// secure service configuration
	srv := httptest.NewTLSServer(&jwt.Handler{
		Target: http.DefaultServeMux,
		Keys:   &jwt.KeyRegister{EdDSAs: []ed25519.PublicKey{EdPublicKey}},

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
	if err := claims.EdDSASignHeader(req, EdPrivateKey); err != nil {
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
	now := time.Unix(1537622794, 0)
	c := jwt.Claims{
		Registered: jwt.Registered{
			Issuer:    "a",
			Subject:   "b",
			Audiences: []string{"c"},
			Expires:   jwt.NewNumericTime(now.Add(time.Minute)),
			NotBefore: jwt.NewNumericTime(now.Add(-time.Second)),
			Issued:    jwt.NewNumericTime(now),
			ID:        "d",
		},
		Set: map[string]interface{}{
			"ext": "e",
		},
	}

	for _, name := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "ext"} {
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
	// "ext": "e"
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
	var c jwt.Claims
	c.Set = map[string]interface{}{
		"deadline": jwt.NewNumericTime(time.Date(1991, 4, 12, 23, 59, 59, 0, time.UTC)),
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
		Keys: &jwt.KeyRegister{ECDSAs: []*ecdsa.PublicKey{ECPublicKey}},
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
	if err := c.ECDSASignHeader(req, jwt.ES512, ECPrivateKey); err != nil {
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
		Keys: &jwt.KeyRegister{RSAs: []*rsa.PublicKey{RSAPublicKey}},
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
	if err := new(jwt.Claims).RSASignHeader(req, jwt.PS512, RSAPrivateKey); err != nil {
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
	_, err := keys.LoadJWK([]byte(json))
	if err != nil {
		fmt.Println("load error:", err)
	}
	fmt.Printf("got %d EdDSA %q", len(keys.EdDSAs), keys.EdDSAIDs)
	fmt.Printf(" + %d secret %q", len(keys.Secrets), keys.SecretIDs)
	// Output:
	// got 1 EdDSA ["kazak"] + 1 secret ["good old"]
}
