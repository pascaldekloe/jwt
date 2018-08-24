package jwt

import (
	"encoding/json"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckHeaderPresent(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ECDSACheckHeader(req, nil)
	if err != ErrNoHeader {
		t.Errorf("ECDSA check got %v, want %v", err, ErrNoHeader)
	}
	_, err = HMACCheckHeader(req, nil)
	if err != ErrNoHeader {
		t.Errorf("HMAC check got %v, want %v", err, ErrNoHeader)
	}
	_, err = RSACheckHeader(req, &testKeyRSA1024.PublicKey)
	if err != ErrNoHeader {
		t.Errorf("RSA check got %v, want %v", err, ErrNoHeader)
	}
}

func TestCheckHeaderSchema(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic QWxhZGRpbjpPcGVuU2VzYW1l")

	_, err = ECDSACheckHeader(req, nil)
	if err != errAuthSchema {
		t.Errorf("ECDSA check got %v, want %v", err, errAuthSchema)
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

func TestSignBrokenClaimsHeader(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// JSON does not allow NaN
	n := NumericTime(math.NaN())

	c := new(Claims)
	c.Issued = &n
	err = c.ECDSASignHeader(req, ES256, testKeyEC256)
	if _, ok := err.(*json.UnsupportedValueError); !ok {
		t.Errorf("ECDSA got error %#v, want json.UnsupportedValueError", err)
	}
	err = c.HMACSignHeader(req, HS256, nil)
	if _, ok := err.(*json.UnsupportedValueError); !ok {
		t.Errorf("HMAC got error %#v, want json.UnsupportedValueError", err)
	}

	c = new(Claims)
	c.Set = map[string]interface{}{"iss": n}
	err = c.RSASignHeader(req, RS256, testKeyRSA1024)
	if _, ok := err.(*json.UnsupportedValueError); !ok {
		t.Errorf("RSA got error %#v, want json.UnsupportedValueError", err)
	}
}

func testUnauthorized(t *testing.T, claims *Claims) (body, header string) {
	srv := httptest.NewServer(&Handler{
		Target: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("handler called")
		}),
		RSAKey: &testKeyRSA2048.PublicKey,
		HeaderBinding: map[string]string{
			"iss": "X-Verified-Issuer",
		},
	})
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if claims != nil {
		if err := claims.RSASignHeader(req, RS512, testKeyRSA2048); err != nil {
			t.Fatal("sign error:", err)
		}
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
	body, header := testUnauthorized(t, nil)

	if want := "jwt: no HTTP Authorization\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := "Bearer"; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}
}

func TestHandleExpire(t *testing.T) {
	claims := new(Claims)
	claims.Expires = NewNumericTime(time.Now().Add(-time.Minute))
	body, header := testUnauthorized(t, claims)

	if want := "jwt: time constraints exceeded\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := `Bearer error="invalid_token", error_description="jwt: time constraints exceeded"`; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}
}

func TestHandleBindingMiss(t *testing.T) {
	claims := new(Claims)
	body, header := testUnauthorized(t, claims)

	if want := "jwt: want string for claim iss\n"; body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if want := `Bearer error="invalid_token", error_description="jwt: want string for claim iss"`; header != want {
		t.Errorf("got WWW-Authenticate %q, want %q", header, want)
	}
}

func TestHandleSchemaMiss(t *testing.T) {
	srv := httptest.NewServer(&Handler{
		Target: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("handler called")
		}),
	})
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic QWxhZGRpbjpPcGVuU2VzYW1l")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}

	if want := "401 Unauthorized"; resp.Status != want {
		t.Errorf("got status %q, want %q", resp.Status, want)
	}
	if got, want := resp.Header.Get("WWW-Authenticate"), `Bearer error="invalid_token", error_description="jwt: want Bearer schema"`; got != want {
		t.Errorf("got WWW-Authenticate %q, want %q", got, want)
	}

	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/") {
		t.Errorf("got content type %q; want text", got)
	}
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(bytes), "jwt: want Bearer schema\n"; got != want {
		t.Errorf("got body %q, want %q", got, want)
	}
}
