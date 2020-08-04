package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/pascaldekloe/jwt"
)

// Note how the security model is flawed without any purpose claims.
// The bare minimum should include time constraints like Expires.
func ExampleClaims() {
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
	token, err := c.RSASign(jwt.RS256, RSAKey)
	if err != nil {
		fmt.Println("token creation failed on", err)
		return
	}

	// verify a JWT
	claims, err := jwt.RSACheck(token, &RSAKey.PublicKey)
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
			"nde": true,
		},
	}

	for _, name := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "ext", "nde"} {
		if s, ok := c.String(name); ok {
			fmt.Printf("%q: %q\n", name, s)
		}
		if n, ok := c.Number(name); ok {
			fmt.Printf("%q: %0.f\n", name, n)
		}
		if b, ok := c.Set[name].(bool); ok {
			fmt.Printf("%q: %t\n", name, b)
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
	// "nde": true
}

func ExampleHandler() {
	// standard HTTP handler
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello %s!\n", req.Header.Get("X-Verified-Name"))
		fmt.Fprintf(w, "You are authorized as %s.\n", req.Header.Get("X-Verified-User"))
	})

	// secure service configuration
	srv := httptest.NewTLSServer(&jwt.Handler{
		Target:       http.DefaultServeMux,
		Keys:         &jwt.KeyRegister{EdDSAs: []ed25519.PublicKey{EdPublicKey}},
		HeaderPrefix: "X-Verified-",
		HeaderBinding: map[string]string{
			"sub": "X-Verified-User", // registered [standard] claim name
			"fn":  "X-Verified-Name", // private [custom] claim name
		},
	})
	defer srv.Close()

	// call service
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJFZERTQSJ9.eyJmbiI6IkxhbmEgQW50aG9ueSBLYW5lIiwic3ViIjoibGFrYW5lIn0.B0DpTbticlRJN8y867gmylujJdfHRnnrFF_nTPkpYbVt9-1Ne1-YawzQxzOQXyZa7HwoU-Um8jOI_Fh8xubjAg")
	resp, _ := srv.Client().Do(req)
	fmt.Println("HTTP", resp.Status)
	io.Copy(os.Stdout, resp.Body)
	// Output:
	// HTTP 200 OK
	// Hello Lana Anthony Kane!
	// You are authorized as lakane.
}

// Claims From Request Context
func ExampleHandler_context() {
	const claimsKey = "verified-jwt"

	// secure service configuration
	h := &jwt.Handler{
		Target: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			claims := req.Context().Value(claimsKey).(*jwt.Claims)
			if n, ok := claims.Number("deadline"); !ok {
				fmt.Fprintln(w, "no deadline")
			} else {
				fmt.Fprintln(w, "deadline at", (*jwt.NumericTime)(&n))
			}
		}),
		Keys:       &jwt.KeyRegister{Secrets: [][]byte{[]byte("killarcherdie")}},
		ContextKey: claimsKey,
	}

	// call service
	req := httptest.NewRequest("GET", "/status", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzM4NCJ9.eyJkZWFkbGluZSI6NjcxNTAwNzk5fQ.HS3mmHVfgP9EMpV4LLzagc6BB1P9J9Yh5TRA9DQHS4GeEejqMaBX0N4LAsMPgW0G")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	fmt.Println("HTTP", resp.Code)
	fmt.Println(resp.Body)
	// Output:
	// HTTP 200
	// deadline at 1991-04-12T23:59:59Z
}

func ExampleHandler_error() {
	// secure service configuration
	h := &jwt.Handler{
		Target: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "My plan is to crowdsource a plan!")
		}),
		Keys: &jwt.KeyRegister{ECDSAs: []*ecdsa.PublicKey{&ECKey.PublicKey}},
		// customise with JSON messages
		Error: func(w http.ResponseWriter, error string, statusCode int) {
			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			w.WriteHeader(statusCode)
			fmt.Fprintf(w, `{"msg": %q}`, error)
		},
	}

	// call service with expired token
	req := httptest.NewRequest("GET", "/had-something-for-this", nil)
	var c jwt.Claims
	c.Expires = jwt.NewNumericTime(time.Now().Add(-time.Second))
	if err := c.ECDSASignHeader(req, jwt.ES512, ECKey); err != nil {
		fmt.Println("sign error:", err)
	}
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
	// secure service configuration
	h := &jwt.Handler{
		Target: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "Elaborate voicemail hoax!")
		}),
		Keys: &jwt.KeyRegister{RSAs: []*rsa.PublicKey{&RSAKey.PublicKey}},
		Func: func(w http.ResponseWriter, req *http.Request, claims *jwt.Claims) (pass bool) {
			if claims.Subject != "marcher" {
				http.Error(w, "Ring, ring!", http.StatusServiceUnavailable)
				return false
			}

			return true
		},
	}

	// call service
	req := httptest.NewRequest("GET", "/urgent", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJQUzI1NiJ9.e30.KSfpjI7WFxGjI0t7NEqPFpcOkEQfR9YiK0nRxDqA7Eoz3X2Af4MhDTgHy4tTXwNBCpW0K-fjMfRG0E34nnsFWsUqFLuMq-geftUUf9aA7E2jrfcZUgi5-FlvOCk8P-iAbqfX0rTIyEBQ21huv75NdYnlfg_2RNd8YqhtxyqTPEjlb0_oLigGEYM6T0eySjNv8V-W2w97HBABHjEaP9aNqj2q_ZB5qERJ-qKP--JYGNx-rTaydFnDAIyWgbRIG2X9IaCRWKe-R8Qz3t76OkZIm7lXiDuYk7aMmfhtSrDL80bpTWGqyQ9AOxAKOTVNTRoTr3Z5cGxrg6B6p3fs4thvFw")
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

// SecretJWK is an example key from RFC 7515, appendix A.1.1.
const SecretJWK = `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`

// Secret is the key value from SecretJWK.
var Secret = []uint8{0x3, 0x23, 0x35, 0x4b, 0x2b, 0xf, 0xa5, 0xbc, 0x83, 0x7e, 0x6, 0x65, 0x77, 0x7b, 0xa6, 0x8f, 0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28, 0xa9, 0xf, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf, 0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x6, 0x47, 0xef, 0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22, 0x3d, 0x2e, 0x21, 0x72, 0x5, 0x2e, 0x4f, 0x8, 0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3}

// RSAJWK is an example key from RFC 7515, appendix A.2.1.
const RSAJWK = `{"kty":"RSA",
      "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
      "e":"AQAB",
      "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
      "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
      "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
      "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
      "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
      "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
     }`

// RSAPEM is a PKCS #1 form of RSAJWK.
const RSAPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd/wWJcyQoTbji9k0
l8W26mPddxHmfHQp+Vaw+4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL+yRT+SFd2lZS+pC
gNMsD1W/YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb/7OMg0LOL+bSf63kpaSHSX
ndS5z5rexMdbBYUsLA9e+KXBdQOS+UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uD
Zlxvb3qCo5ZwKh9kG4LT6/I5IhlJH7aGhyxXFvUK+DWNmoudF8NAco9/h9iaGNj8
q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQIDAQABAoIBABKucaRpzQorw35S
bEUAVx8dYXUdZOlJcHtiWQ+dC6V8ljxAHj/PLyzTveyI5QO/xkObCyjIL303l2cf
UhPu2MFaJdjVzqACXuOrLot/eSFvxjvqVidTtAZExqFRJ9mylUVAoLvhowVWmC1O
n95fZCXxTUtxNEG1Xcc7m0rtzJKs45J+N/V9DP1edYH6USyPSWGp6wuA+KgHRnKK
Vf9GRx80JQY7nVNkL17eHoTWEwga+lwi0FEoW9Y7lDtWXYmKBWhUE+U8PGxlJf8f
40493HDw1WRQ/aSLoS4QTp3rn7gYgeHEvfJdkkf0UMhlknlo53M09EFPdadQ4TlU
bjqKc50CgYEA4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH/5IB3jw3bcxGn6QLvnE
tfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw/Py5PJdTJNPY8cQn7ouZ2KKDcmnPG
BY5t7yLc1QlQ5xHdwW1VhvKn+nXqhJTBgIPgtldC+KDV5z+y2XDwGUcCgYEAuQPE
fgmVtjL0Uyyx88GZFF1fOunH3+7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYs
p1ZSe7zFYHj7C6ul7TjeLQeZD/YwD66t62wDmpe/HlB+TnBA+njbglfIsRLtXlnD
zQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdcCgYAHAp9XcCSrn8wVkMVkKdb7
DOX4IKjzdahm+ctDAJN4O/y7OW5FKebvUjdAIt2GuoTZ71iTG+7F0F+lP88jtjP4
U4qe7VHoewl4MKOfXZKTe+YCS1XbNvfgwJ3Ltyl1OH9hWvu2yza7q+d5PCsDzqtm
27kxuvULVeya+TEdAB1ijQKBgQCH/3r6YrVH/uCWGy6bzV1nGNOdjKc9tmkfOJmN
54dxdixdpozCQ6U4OxZrsj3FcOhHBsqAHvX2uuYjagqvo3cOj1TRqNocX40omfCC
Mx3bD1yPPf/6TI2XECva/ggqEY2mYzmIiA5LVVmc5nrybr+lssFKneeyxN2Wq93S
0iJMdQKBgCGHewxzoa1r8ZMD0LETNrToK423K377UCYqXfg5XMclbrjPbEC3YI1Z
NqMtuhdBJqUnBi6tjKMF+34Xf0CUN8ncuXGO2CAYvO8PdyCixHX52ybaDjy1FtCE
6yUXjoKNXKvUm7MWGsAYH6f4IegOetN5NvmUMFStCSkh7ixZLkN1
-----END RSA PRIVATE KEY-----`

// ECJWK is an example key from RFC 7515, appendix A.3.1.
const ECJWK = `{"kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
     }`

// ECPEM is a PKCS #8 form of ECJWK.
const ECPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjpsQnnGQmL+YBIff
H1136cspYG6+0iY7X1fCE9+E9LKhRANCAAR/zc4ncPbEXUGDy+5v20t7WAczNXvp
7xO6z248e9FURcfxRM0bvZt+hyzf7bnuufSzaV1uqQskrYpGIyiFiOWt
-----END PRIVATE KEY-----`

// EdJWK is an example key from RFC 8037, appendix A.1.
//lint:ignore U1000 reserved for future use
const EdJWK = `{"kty":"OKP","crv":"Ed25519",
   "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
   "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

// EdPublicJWK is an example key from RFC 8037, appendix A.2.
//lint:ignore U1000 reserved for future use
const EdPublicJWK = `{"kty":"OKP","crv":"Ed25519",
   "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

// EdKey is an example key from RFC 8037, appendix A.1.
//lint:ignore U1000 reserved for future use
var EdKey = append(ed25519.PrivateKey{
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
	0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
	0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
}, EdPublicKey...)

// EdPublicKey is an example key from RFC 8037, appendix A.1.
var EdPublicKey = ed25519.PublicKey{
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
}

var ECKey = mustParseECKey(ECPEM)

func mustParseECKey(s string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		panic("no PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key.(*ecdsa.PrivateKey)
}

var RSAKey = mustParseRSAKey(RSAPEM)

func mustParseRSAKey(s string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		panic("no PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

func TestSecret(t *testing.T) {
	// example from RFC 7515, appendix A.1.1.
	const token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	_, err := jwt.HMACCheck([]byte(token), Secret)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecretJWK(t *testing.T) {
	// example from RFC 7515, appendix A.1.
	const token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	var keys jwt.KeyRegister
	n, err := keys.LoadJWK([]byte(SecretJWK))
	if n != 1 || err != nil {
		t.Fatalf("LoadJWK(%q) got (%d, %v), want (1, nil)", SecretJWK, n, err)
	}
	_, err = keys.Check([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
}

func TestRSAJWK(t *testing.T) {
	// example from RFC 7515, appendix A.2.
	const token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

	var keys jwt.KeyRegister
	n, err := keys.LoadJWK([]byte(RSAJWK))
	if n != 1 || err != nil {
		t.Fatalf("LoadJWK(%q) got (%d, %v), want (1, nil)", RSAJWK, n, err)
	}
	_, err = keys.Check([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
}

func TestRSAPEM(t *testing.T) {
	// example from RFC 7515, appendix A.2.
	const token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

	var keys jwt.KeyRegister
	n, err := keys.LoadPEM([]byte(RSAPEM), nil)
	if n != 1 || err != nil {
		t.Fatalf("LoadPEM(%q, nil) got (%d, %v), want (1, nil)", RSAPEM, n, err)
	}
	_, err = keys.Check([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
}

func TestECJWK(t *testing.T) {
	// example from RFC 7515, appendix A.3.
	const token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

	var keys jwt.KeyRegister
	n, err := keys.LoadJWK([]byte(ECJWK))
	if n != 1 || err != nil {
		t.Fatalf("LoadJWK(%q) got (%d, %v), want (1, nil)", ECJWK, n, err)
	}
	_, err = keys.Check([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
}

func TestECPEM(t *testing.T) {
	// example from RFC 7515, appendix A.3.
	const token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

	var keys jwt.KeyRegister
	n, err := keys.LoadPEM([]byte(ECPEM), nil)
	if n != 1 || err != nil {
		t.Fatalf("LoadPEM(%q, nil) got (%d, %v), want (1, nil)", ECPEM, n, err)
	}
	_, err = keys.Check([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
}
