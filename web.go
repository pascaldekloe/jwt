package jwt

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MIMEType is the IANA registered media type.
const MIMEType = "application/jwt"

// OAuthURN is the IANA registered OAuth URI.
const OAuthURN = "urn:ietf:params:oauth:token-type:jwt"

// ErrNoHeader signals an HTTP request without Authorization.
var ErrNoHeader = errors.New("jwt: no Authorization header")

var errAuthSchema = errors.New("jwt: want Bearer schema")

// HMACCheckHeader applies HMACCheck on a HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func HMACCheckHeader(r *http.Request, secret []byte) (*Claims, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, ErrNoHeader
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, errAuthSchema
	}
	return HMACCheck([]byte(auth[7:]), secret)
}

// RSACheckHeader applies RSACheck on a HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func RSACheckHeader(r *http.Request, key *rsa.PublicKey) (*Claims, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, ErrNoHeader
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, errAuthSchema
	}
	return RSACheck([]byte(auth[7:]), key)
}

// HMACSignHeader applies HMACSign on a HTTP request.
// Specifically it sets a bearer token in the Authorization header.
func (c *Claims) HMACSignHeader(r *http.Request, alg string, secret []byte) error {
	token, err := c.HMACSign(alg, secret)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+string(token))
	return nil
}

// RSASignHeader applies RSASign on a HTTP request.
// Specifically it sets a bearer token in the Authorization header.
func (c *Claims) RSASignHeader(r *http.Request, alg string, key *rsa.PrivateKey) error {
	token, err := c.RSASign(alg, key)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+string(token))
	return nil
}

// Handler protects an http.Handler with security enforcements.
// Requests are passed to Target only when the JWT checks out.
type Handler struct {
	// Target is the secured service.
	Target http.Handler

	// Secret is the HMAC key.
	Secret []byte
	// RSAKey applies RSAAlgs and disables HMACAlgs when set.
	RSAKey *rsa.PublicKey

	// HeaderBinding maps JWT claim names to HTTP header names.
	// All requests passed to Target have these headers set. In
	// case of failure the request is rejected with status code
	// 401 (Unauthorized) and a description.
	HeaderBinding map[string]string

	// Func is called after the JWT validation succeeds and
	// before any header bindings. Requests are dropped when
	// the return is false.
	Func func(http.ResponseWriter, *http.Request, *Claims) (pass bool)
}

// ServeHTTP honors the http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// verify claims
	var claims *Claims
	var err error
	if h.RSAKey != nil {
		claims, err = RSACheckHeader(r, h.RSAKey)
	} else {
		claims, err = HMACCheckHeader(r, h.Secret)
	}
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description=`+strconv.Quote(err.Error()))
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// verify time constraints
	if !claims.Valid(time.Now()) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="jwt: time constraints exceeded"`)
		http.Error(w, "jwt: time constraints exceeded", http.StatusUnauthorized)
		return
	}

	// apply the custom function when set
	if h.Func != nil && !h.Func(w, r, claims) {
		return
	}

	// claim propagation
	for claimName, headerName := range h.HeaderBinding {
		s, ok := claims.String(claimName)
		if !ok {
			msg := "jwt: want string for claim " + claimName
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description=`+strconv.Quote(msg))
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		r.Header.Set(headerName, s)
	}

	h.Target.ServeHTTP(w, r)
}
