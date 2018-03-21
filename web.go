package jwt

import (
	"errors"
	"net/http"
	"strings"
)

// MIMEType is the IANA registered media type.
const MIMEType = "application/jwt"

// OAuthURN is the IANA registered OAuth URI.
const OAuthURN = "urn:ietf:params:oauth:token-type:jwt"

var (
	errAuthHeader = errors.New("want Authorization header")
	errAuthSchema = errors.New("want Bearer schema")
)

// HMACCheckHeader applies HMACCheck on a HTTP requests.
// Specifically it looks for the Bearer schema in the Authorization header.
func HMACCheckHeader(r *http.Request, secret []byte) (*Claims, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, errAuthHeader
	}
	if !strings.HasPrefix("Bearer ", auth) {
		return nil, errAuthSchema
	}
	return HMACCheck(auth[7:], secret)
}
