package jwt

import (
	"crypto/ecdsa"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckHeaderPresent(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ECDSACheckHeader(req, &testKeyEC256.PublicKey)
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
	_, err = new(KeyPool).CheckHeader(req)
	if err != ErrNoHeader {
		t.Errorf("KeyPool check got %v, want %v", err, ErrNoHeader)
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
	_, err = HMACCheckHeader(req, nil)
	if err != errAuthSchema {
		t.Errorf("HMAC check got %v, want %v", err, errAuthSchema)
	}
	_, err = RSACheckHeader(req, &testKeyRSA1024.PublicKey)
	if err != errAuthSchema {
		t.Errorf("RSA check got %v, want %v", err, errAuthSchema)
	}
}

func TestSignHeaderErrPass(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	unknownAlg := "doesnotexist"
	want := ErrAlgUnk

	c := new(Claims)
	if err := c.ECDSASignHeader(req, unknownAlg, testKeyEC256); err != want {
		t.Errorf("ECDSA got error %v, want %v", err, want)
	}
	if err := c.HMACSignHeader(req, unknownAlg, nil); err != want {
		t.Errorf("HMAC got error %v, want %v", err, want)
	}
	if err := c.RSASignHeader(req, unknownAlg, testKeyRSA1024); err != want {
		t.Errorf("RSA got error %v, want %v", err, want)
	}
}

func testUnauthorized(t *testing.T, reqHeader string) (body, header string) {
	srv := httptest.NewServer(&Handler{
		Target: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("handler called")
		}),
		KeyPool: &KeyPool{
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

	if want := "jwt: no HTTP Authorization\n"; body != want {
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
