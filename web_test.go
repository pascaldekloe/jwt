package jwt

import (
	"encoding/json"
	"math"
	"net/http"
	"testing"
)

func TestHeaderCycle(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// HMAC case already covered by package level example.

	c := new(Claims)
	c.Audience = "test"
	if err := c.RSASignHeader(req, RS384, testKeyRSA1024); err != nil {
		t.Fatal("sign error:", err)
	}

	got, err := RSACheckHeader(req, &testKeyRSA1024.PublicKey)
	if err != nil {
		t.Fatal("check error:", err)
	}
	if got.Audience != c.Audience {
		t.Errorf("got audience %q, want %q", got.Audience, c.Audience)
	}
}

func TestCheckHeaderPresent(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = HMACCheckHeader(req, nil)
	if err != errAuthHeader {
		t.Errorf("HMAC check got %v, want %v", err, errAuthHeader)
	}
	_, err = RSACheckHeader(req, &testKeyRSA1024.PublicKey)
	if err != errAuthHeader {
		t.Errorf("RSA check got %v, want %v", err, errAuthHeader)
	}
}

func TestCheckHeaderSchema(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic QWxhZGRpbjpPcGVuU2VzYW1l")

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
