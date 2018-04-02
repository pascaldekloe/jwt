package jwt

import "net/http"
import "testing"

func TestCheckHeaderPresent(t *testing.T) {
	r := new(http.Request)
	_, err := HMACCheckHeader(r, nil)
	if err != errAuthHeader {
		t.Errorf("HMAC check got %v, want %v", err, errAuthHeader)
	}
	_, err = RSACheckHeader(r, &testKeyRSA1024.PublicKey)
	if err != errAuthHeader {
		t.Errorf("RSA check got %v, want %v", err, errAuthHeader)
	}
}

func TestCheckHeaderSchema(t *testing.T) {
	r := new(http.Request)
	r.Header = http.Header{"Authorization": []string{"Basic QWxhZGRpbjpPcGVuU2VzYW1l"}}

	_, err := HMACCheckHeader(r, nil)
	if err != errAuthSchema {
		t.Errorf("HMAC check got %v, want %v", err, errAuthSchema)
	}
	_, err = RSACheckHeader(r, &testKeyRSA1024.PublicKey)
	if err != errAuthSchema {
		t.Errorf("RSA check got %v, want %v", err, errAuthSchema)
	}
}
