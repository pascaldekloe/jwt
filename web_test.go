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

func TestCheckHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)

	req.Header.Set("Authorization", "Bearer "+goldenECDSAs[0].token)
	if _, err := ECDSACheckHeader(req, goldenECDSAs[0].key); err != nil {
		t.Errorf("ECDSA %q error: %s", req.Header.Get("Authorization"), err)
	}
	req.Header.Set("Authorization", "BEARER "+goldenEdDSAs[0].token)
	if _, err := EdDSACheckHeader(req, goldenEdDSAs[0].key); err != nil {
		t.Errorf("EdDSA %q error: %s", req.Header.Get("Authorization"), err)
	}
	req.Header.Set("Authorization", "bearer "+goldenHMACs[0].token)
	if _, err := HMACCheckHeader(req, goldenHMACs[0].secret); err != nil {
		t.Errorf("HMAC %q error: %s", req.Header.Get("Authorization"), err)
	}
	if h, err := NewHMAC(HS256, goldenHMACs[0].secret); err != nil {
		t.Errorf("NewHMAC error: %s", err)
	} else if _, err := h.CheckHeader(req); err != nil {
		t.Errorf("reusable HMAC %q error: %s", req.Header.Get("Authorization"), err)
	}
	req.Header.Set("Authorization", "bEArEr "+goldenRSAs[0].token)
	if _, err := RSACheckHeader(req, goldenRSAs[0].key); err != nil {
		t.Errorf("RSA %q error: %s", req.Header.Get("Authorization"), err)
	}
}

func TestCheckHeadersPresence(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)

	if _, err := ECDSACheckHeader(req, &testKeyEC256.PublicKey); err != ErrNoHeader {
		t.Errorf("ECDSA check got %v, want %v", err, ErrNoHeader)
	}
	if _, err := EdDSACheckHeader(req, testKeyEd25519Public); err != ErrNoHeader {
		t.Errorf("EdDSA check got %v, want %v", err, ErrNoHeader)
	}
	if _, err := HMACCheckHeader(req, nil); err != ErrNoHeader {
		t.Errorf("HMAC check got %v, want %v", err, ErrNoHeader)
	}
	if h, err := NewHMAC(HS256, []byte("arbitary")); err != nil {
		t.Errorf("NewHMAC error: %s", err)
	} else if _, err := h.CheckHeader(req); err != ErrNoHeader {
		t.Errorf("reusable HMAC check got %v, want %v", err, ErrNoHeader)
	}
	if _, err := RSACheckHeader(req, &testKeyRSA1024.PublicKey); err != ErrNoHeader {
		t.Errorf("RSA check got %v, want %v", err, ErrNoHeader)
	}
	if _, err := new(KeyRegister).CheckHeader(req); err != ErrNoHeader {
		t.Errorf("KeyRegister check got %v, want %v", err, ErrNoHeader)
	}
}

func TestCheckHeadersSchema(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic QWxhZGRpbjpPcGVuU2VzYW1l")
	if _, err := ECDSACheckHeader(req, &testKeyEC256.PublicKey); err != errAuthSchema {
		t.Errorf("ECDSA check got %v, want %v", err, errAuthSchema)
	}
	if _, err := EdDSACheckHeader(req, testKeyEd25519Public); err != errAuthSchema {
		t.Errorf("EdDSA check got %v, want %v", err, errAuthSchema)
	}
	if _, err := HMACCheckHeader(req, nil); err != errAuthSchema {
		t.Errorf("HMAC check got %v, want %v", err, errAuthSchema)
	}
	if h, err := NewHMAC(HS256, []byte("arbitary")); err != nil {
		t.Errorf("NewHMAC error: %s", err)
	} else if _, err := h.CheckHeader(req); err != errAuthSchema {
		t.Errorf("reusable HMAC check got %v, want %v", err, errAuthSchema)
	}
	if _, err := RSACheckHeader(req, &testKeyRSA1024.PublicKey); err != errAuthSchema {
		t.Errorf("RSA check got %v, want %v", err, errAuthSchema)
	}
	if _, err := new(KeyRegister).CheckHeader(req); err != errAuthSchema {
		t.Errorf("KeyRegister check got %v, want %v", err, errAuthSchema)
	}
}

func TestCheckHeadersAlg(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	// example from RFC 7519, subsection 6.1
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.")
	const want = AlgError("none")

	if _, err := ECDSACheckHeader(req, &testKeyEC256.PublicKey); err != want {
		t.Errorf("ECDSA got error %v, want %v", err, want)
	}
	if _, err := EdDSACheckHeader(req, testKeyEd25519Public); err != want {
		t.Errorf("ECDSA got error %v, want %v", err, want)
	}
	if _, err := HMACCheckHeader(req, []byte("guest")); err != want {
		t.Errorf("HMAC got error %v, want %v", err, want)
	}
	if h, err := NewHMAC(HS256, []byte("guest")); err != nil {
		t.Errorf("NewHMAC error: %s", err)
	} else if _, err := h.CheckHeader(req); err != want {
		t.Errorf("resuable HMAC got error %v, want %v", err, want)
	}
	if _, err := RSACheckHeader(req, &testKeyRSA1024.PublicKey); err != want {
		t.Errorf("RSA got error %v, want %v", err, want)
	}
	if _, err := new(KeyRegister).CheckHeader(req); err != want {
		t.Errorf("KeyRegister check got %v, want %v", err, want)
	}
}

func TestSignHeaders(t *testing.T) {
	var c Claims
	req := httptest.NewRequest("GET", "/", nil)

	if err := c.ECDSASignHeader(req, ES256, testKeyEC256); err != nil {
		t.Error("ECDSA error:", err)
	} else if _, err = ECDSACheckHeader(req, &testKeyEC256.PublicKey); err != nil {
		t.Errorf("ECDSA check %q error: %s", req.Header.Get("Authorization"), err)
	}
	if err := c.EdDSASignHeader(req, testKeyEd25519Private); err != nil {
		t.Error("EdDSA error:", err)
	} else if _, err = EdDSACheckHeader(req, testKeyEd25519Public); err != nil {
		t.Errorf("EdDSA check %q error: %s", req.Header.Get("Authorization"), err)
	}
	if err := c.HMACSignHeader(req, HS256, []byte("guest")); err != nil {
		t.Error("HMAC error:", err)
	} else if _, err = HMACCheckHeader(req, []byte("guest")); err != nil {
		t.Errorf("HMAC check %q error: %s", req.Header.Get("Authorization"), err)
	}
	if h, err := NewHMAC(HS256, []byte("guest")); err != nil {
		t.Errorf("NewHMAC error: %s", err)
	} else if err := h.SignHeader(&c, req); err != nil {
		t.Error("reusable HMAC error:", err)
	} else if _, err = h.CheckHeader(req); err != nil {
		t.Errorf("reusable HMAC check %q error: %s", req.Header.Get("Authorization"), err)
	}
	if err := c.RSASignHeader(req, RS256, testKeyRSA1024); err != nil {
		t.Error("RSA error:", err)
	} else if _, err = RSACheckHeader(req, &testKeyRSA1024.PublicKey); err != nil {
		t.Errorf("RSA check %q error: %s", req.Header.Get("Authorization"), err)
	}
}

func TestSignHeadersError(t *testing.T) {
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
	h, err := NewHMAC(HS256, []byte("guest"))
	if err != nil {
		t.Errorf("NewHMAC error: %s", err)
	}
	err = h.SignHeader(&c, req)
	if _, ok := err.(*json.UnsupportedValueError); !ok {
		t.Errorf("reusable HMAC got error %#v, want json.UnsupportedValueError", err)
	}
	err = c.RSASignHeader(req, RS256, testKeyRSA1024)
	if _, ok := err.(*json.UnsupportedValueError); !ok {
		t.Errorf("RSA got error %#v, want json.UnsupportedValueError", err)
	}
}

func TestHandlerHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Verified-Injection", "attempt to pollute namespace")
	var claims Claims
	claims.ID = "test ID"
	if err := claims.EdDSASignHeader(req, testKeyEd25519Private); err != nil {
		t.Fatal(err)
	}

	handler := Handler{
		HeaderPrefix: "vErified-",
		HeaderBinding: map[string]string{
			"jti": "VeRified-header",
		},
		Func: func(w http.ResponseWriter, req *http.Request, claims *Claims) (pass bool) {
			if _, ok := req.Header[http.CanonicalHeaderKey("Verified-Injection")]; ok {
				t.Error("header injection present at JWT Handler Func")
			}
			if _, ok := req.Header[http.CanonicalHeaderKey("Verified-Header")]; ok {
				t.Error("header binding present at JWT Handler Func")
			}
			fmt.Fprintln(w, "✓ func")
			return true
		},
		Target: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Header.Get("Verified-Injection") != "" {
				t.Error("header injection present at HTTP Handler")
			}
			if got := strings.Join(req.Header[http.CanonicalHeaderKey("Verified-Header")], ","); got != "test ID" {
				t.Errorf("bound header value got %q, want test ID", got)
			}
			fmt.Fprintln(w, "✓ handler")
		}),
		Keys: &KeyRegister{EdDSAs: []ed25519.PublicKey{testKeyEd25519Public}},
	}

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if want := "✓ func\n✓ handler\n"; resp.Body.String() != want {
		t.Errorf("got HTTP body %q, want %q", resp.Body, want)
	}
}

func TestHandlerHeaderPrefixBindingMismatch(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if err := new(Claims).EdDSASignHeader(req, testKeyEd25519Private); err != nil {
		t.Fatal(err)
	}

	handler := Handler{
		HeaderPrefix: "vErified-",
		HeaderBinding: map[string]string{
			"jti": "not-within-prefix",
		},
		Target: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			t.Error("target handler invoked")
		}),
		Keys: &KeyRegister{EdDSAs: []ed25519.PublicKey{testKeyEd25519Public}},
	}

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != 500 || !strings.Contains(resp.Body.String(), "prefix mismatch") {
		t.Errorf("got HTTP %d %q, want HTTP 500 prefix mismatch", resp.Code, resp.Body)
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

func TestHandleNoHeader(t *testing.T) {
	body, header := testUnauthorized(t, "")

	if want := "jwt: no HTTP authorization header\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := "Bearer"; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}
}

func TestHandleExpire(t *testing.T) {
	body, header := testUnauthorized(t, "Bearer eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjE1Mzc3OTMwNjYuMjcyNDc3OX0.NPQH3KKXDe9QlyxyGA_ntPfrNyuetNAoOuPe8G5CE8jbwBzJOX8tQRXCXBhmiI5HAUqzqhH1CZuOjqMQKxGntA")

	if want := "jwt: time constraints exceeded\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := `Bearer error="invalid_token", error_description="jwt: time constraints exceeded"`; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}
}

func TestHandleBindingMiss(t *testing.T) {
	body, header := testUnauthorized(t, "Bearer eyJhbGciOiJFUzI1NiJ9.e30.ptu9sJlVNPISJIP4q6I_U7YnaNRldB2paG8V4zKav9P6EM6MksQl0IMRy8mJKevZI2LIS2DA7C1ILnNhEeSo-Q")

	if want := "jwt: want string for claim iss\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := `Bearer error="invalid_token", error_description="jwt: want string for claim iss"`; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}
}

func TestHandleSchemaMiss(t *testing.T) {
	body, header := testUnauthorized(t, "Basic QWxhZGRpbjpPcGVuU2VzYW1l")

	if want := "jwt: want Bearer schema\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := `Bearer error="invalid_token", error_description="jwt: want Bearer schema"`; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}
}
