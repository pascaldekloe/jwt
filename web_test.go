package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckHeader(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+goldenECDSAs[0].token)
	_, err = ECDSACheckHeader(req, goldenECDSAs[0].key)
	if err != nil {
		t.Error("ECDSA error:", err)
	}

	req.Header.Set("Authorization", "Bearer "+goldenEdDSAs[0].token)
	_, err = EdDSACheckHeader(req, goldenEdDSAs[0].key)
	if err != nil {
		t.Error("EdDSA error:", err)
	}

	req.Header.Set("Authorization", "Bearer "+goldenHMACs[0].token)
	_, err = HMACCheckHeader(req, goldenHMACs[0].secret)
	if err != nil {
		t.Error("HMAC error:", err)
	}

	req.Header.Set("Authorization", "Bearer "+goldenRSAs[0].token)
	_, err = RSACheckHeader(req, goldenRSAs[0].key)
	if err != nil {
		t.Error("RSA error:", err)
	}
}

func TestCheckHeaderPresent(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ECDSACheckHeader(req, &testKeyEC256.PublicKey)
	if err != ErrNoHeader {
		t.Errorf("ECDSA check got %v, want %v", err, ErrNoHeader)
	}
	_, err = EdDSACheckHeader(req, testKeyEd25519Public)
	if err != ErrNoHeader {
		t.Errorf("EdDSA check got %v, want %v", err, ErrNoHeader)
	}
	_, err = HMACCheckHeader(req, nil)
	if err != ErrNoHeader {
		t.Errorf("HMAC check got %v, want %v", err, ErrNoHeader)
	}
	_, err = RSACheckHeader(req, &testKeyRSA1024.PublicKey)
	if err != ErrNoHeader {
		t.Errorf("RSA check got %v, want %v", err, ErrNoHeader)
	}
	_, err = new(KeyRegister).CheckHeader(req)
	if err != ErrNoHeader {
		t.Errorf("KeyRegister check got %v, want %v", err, ErrNoHeader)
	}
}

func TestCheckHeaderSchema(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic QWxhZGRpbjpPcGVuU2VzYW1l")

	_, err = ECDSACheckHeader(req, &testKeyEC256.PublicKey)
	if err != errAuthSchema {
		t.Errorf("ECDSA check got %v, want %v", err, errAuthSchema)
	}
	_, err = EdDSACheckHeader(req, testKeyEd25519Public)
	if err != errAuthSchema {
		t.Errorf("EdDSA check got %v, want %v", err, errAuthSchema)
	}
	_, err = HMACCheckHeader(req, nil)
	if err != errAuthSchema {
		t.Errorf("HMAC check got %v, want %v", err, errAuthSchema)
	}
	_, err = RSACheckHeader(req, &testKeyRSA1024.PublicKey)
	if err != errAuthSchema {
		t.Errorf("RSA check got %v, want %v", err, errAuthSchema)
	}
}

func TestCheckHeaderError(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	// example from RFC 7519, subsection 6.1.
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.")
	want := AlgError("none")

	if _, err := ECDSACheckHeader(req, &testKeyEC256.PublicKey); err != want {
		t.Errorf("ECDSA got error %v, want %v", err, want)
	}
	if _, err := EdDSACheckHeader(req, testKeyEd25519Public); err != want {
		t.Errorf("ECDSA got error %v, want %v", err, want)
	}
	if _, err := HMACCheckHeader(req, []byte("guest")); err != want {
		t.Errorf("HMAC got error %v, want %v", err, want)
	}
	if _, err := RSACheckHeader(req, &testKeyRSA1024.PublicKey); err != want {
		t.Errorf("RSA got error %v, want %v", err, want)
	}
}

func TestSignHeaderError(t *testing.T) {
	// JSON does not allow NaN
	n := NumericTime(math.NaN())
	var c Claims
	c.Issued = &n
	req := httptest.NewRequest("GET", "/", nil)

	err := c.ECDSASignHeader(req, ES256, testKeyEC256)
	if _, ok := err.(*json.UnsupportedValueError); !ok {
		t.Errorf("ECDSA got error %#v, want json.UnsupportedValueError", err)
	}
	err = c.EdDSASignHeader(req, testKeyEd25519Private)
	if _, ok := err.(*json.UnsupportedValueError); !ok {
		t.Errorf("EdDSA got error %#v, want json.UnsupportedValueError", err)
	}
	err = c.HMACSignHeader(req, HS256, []byte("guest"))
	if _, ok := err.(*json.UnsupportedValueError); !ok {
		t.Errorf("HMAC got error %#v, want json.UnsupportedValueError", err)
	}
	err = c.RSASignHeader(req, RS256, testKeyRSA1024)
	if _, ok := err.(*json.UnsupportedValueError); !ok {
		t.Errorf("RSA got error %#v, want json.UnsupportedValueError", err)
	}
}

func TestHandlerHeaders(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Verified-Injection", "attempt to pollute namespace")
	var claims Claims
	claims.ID = "test"
	claims.Subject = "test"
	if err := claims.EdDSASignHeader(req, testKeyEd25519Private); err != nil {
		t.Fatal(err)
	}

	handler := Handler{
		HeaderPrefix: "Verified-",
		HeaderBinding: map[string]string{
			"jti": "Verified-Header",
			"sub": "Unverified-Header", // prefix doesn't match
		},
		Func: func(w http.ResponseWriter, req *http.Request, claims *Claims) (pass bool) {
			if req.Header.Get("Verified-Injection") != "" {
				t.Error("header injection present at JWT Handler Func")
			}
			if req.Header.Get("Verified-Header") != "" || req.Header.Get("Unverified-Header") != "" {
				t.Error("header binding present at JWT Handler Func")
			}
			fmt.Fprintln(w, "✓ func")
			return true
		},
		Target: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Header.Get("Verified-Injection") != "" {
				t.Error("header injection present at HTTP Handler")
			}
			if req.Header.Get("Verified-Header") == "" {
				t.Error("header match absent at HTTP Handler")
			}
			if req.Header.Get("Unverified-Header") != "" {
				t.Error("header mismatch present at HTTP Handler")
			}
			fmt.Fprintln(w, "✓ handler")
		}),
		Keys: &KeyRegister{EdDSAs: []ed25519.PublicKey{testKeyEd25519Public}},
	}

	const want = "✓ func\n✓ handler\n"
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if got := fmt.Sprint(resp.Body); got != want {
		t.Errorf("got HTTP body %q, want %q", got, want)
	}
}

func testUnauthorized(t *testing.T, reqHeader string) (body, header string) {
	srv := httptest.NewServer(&Handler{
		Target: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("handler called")
		}),
		Keys: &KeyRegister{
			ECDSAs: []*ecdsa.PublicKey{&testKeyEC256.PublicKey},
		},
		HeaderBinding: map[string]string{
			"iss": "X-Verified-Issuer",
		},
	})
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reqHeader != "" {
		req.Header.Set("Authorization", reqHeader)
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if want := "401 Unauthorized"; resp.Status != want {
		t.Errorf("got status %q, want %q", resp.Status, want)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/") {
		t.Errorf("got content type %q; want text", got)
	}
	return string(bytes), resp.Header.Get("WWW-Authenticate")
}

func testUnauthorizedCustom(t *testing.T, reqHeader string) (body, header string) {
	srv := httptest.NewServer(&Handler{
		Target: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("handler called")
		}),
		Keys: &KeyRegister{
			ECDSAs: []*ecdsa.PublicKey{&testKeyEC256.PublicKey},
		},
		HeaderBinding: map[string]string{
			"iss": "X-Verified-Issuer",
		},
		WriteError: func(w http.ResponseWriter, error string, code int) {
			type result struct {
				Status string `json:"status"`
				Message string `json:"message"`
			}
			res := result{
				Status:  "invalid_token",
				Message: error,
			}

			jsonRes, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			w.WriteHeader(code)
			fmt.Fprintln(w, string(jsonRes))

		},
	})
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reqHeader != "" {
		req.Header.Set("Authorization", reqHeader)
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if want := "401 Unauthorized"; resp.Status != want {
		t.Errorf("got status %q, want %q", resp.Status, want)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/") {
		t.Errorf("got content type %q; want application", got)
	}
	return string(bytes), resp.Header.Get("WWW-Authenticate")
}

func TestHandleNoHeader(t *testing.T) {
	body, header := testUnauthorized(t, "")

	if want := "jwt: no HTTP authorization header\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := "Bearer"; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}

	body, header = testUnauthorizedCustom(t, "")
	if want := "{\"status\":\"invalid_token\",\"message\":\"jwt: no HTTP Authorization\"}\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := "Bearer"; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}
}

func TestHandleExpire(t *testing.T) {
	reqHeader := "Bearer eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjE1Mzc3OTMwNjYuMjcyNDc3OX0.NPQH3KKXDe9QlyxyGA_ntPfrNyuetNAoOuPe8G5CE8jbwBzJOX8tQRXCXBhmiI5HAUqzqhH1CZuOjqMQKxGntA"
	body, header := testUnauthorized(t, reqHeader)

	if want := "jwt: time constraints exceeded\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := `Bearer error="invalid_token", error_description="jwt: time constraints exceeded"`; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}

	body, header = testUnauthorizedCustom(t, reqHeader)
	if want := "{\"status\":\"invalid_token\",\"message\":\"jwt: time constraints exceeded\"}\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := `Bearer error="invalid_token", error_description="jwt: time constraints exceeded"`; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}
}

func TestHandleBindingMiss(t *testing.T) {
	reqHeader := "Bearer eyJhbGciOiJFUzI1NiJ9.e30.ptu9sJlVNPISJIP4q6I_U7YnaNRldB2paG8V4zKav9P6EM6MksQl0IMRy8mJKevZI2LIS2DA7C1ILnNhEeSo-Q"
	body, header := testUnauthorized(t, reqHeader)

	if want := "jwt: want string for claim iss\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := `Bearer error="invalid_token", error_description="jwt: want string for claim iss"`; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}

	body, header = testUnauthorizedCustom(t, reqHeader)
	if want := "{\"status\":\"invalid_token\",\"message\":\"jwt: want string for claim iss\"}\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := `Bearer error="invalid_token", error_description="jwt: want string for claim iss"`; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}
}

func TestHandleSchemaMiss(t *testing.T) {
	reqHeader := "Basic QWxhZGRpbjpPcGVuU2VzYW1l"
	body, header := testUnauthorized(t, reqHeader)

	if want := "jwt: want Bearer schema\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := `Bearer error="invalid_token", error_description="jwt: want Bearer schema"`; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}

	body, header = testUnauthorizedCustom(t, reqHeader)
	if want := "{\"status\":\"invalid_token\",\"message\":\"jwt: want Bearer schema\"}\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := `Bearer error="invalid_token", error_description="jwt: want Bearer schema"`; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}
}
