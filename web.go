package jwt

import (
	"context"
	"crypto/ecdsa"
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
var ErrNoHeader = errors.New("jwt: no HTTP Authorization")

var errAuthSchema = errors.New("jwt: want Bearer schema")

// ECDSACheckHeader applies ECDSACheck on a HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func ECDSACheckHeader(r *http.Request, key *ecdsa.PublicKey) (*Claims, error) {
	token, err := tokenFromHeader(r)
	if err != nil {
		return nil, err
	}
	return ECDSACheck(token, key)
}

// HMACCheckHeader applies HMACCheck on a HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func HMACCheckHeader(r *http.Request, secret []byte) (*Claims, error) {
	token, err := tokenFromHeader(r)
	if err != nil {
		return nil, err
	}
	return HMACCheck(token, secret)
}

// RSACheckHeader applies RSACheck on a HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func RSACheckHeader(r *http.Request, key *rsa.PublicKey) (*Claims, error) {
	token, err := tokenFromHeader(r)
	if err != nil {
		return nil, err
	}
	return RSACheck(token, key)
}

// CheckHeader applies KeyRegister.Check on a HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func (keys *KeyRegister) CheckHeader(r *http.Request) (*Claims, error) {
	token, err := tokenFromHeader(r)
	if err != nil {
		return nil, err
	}
	return keys.Check(token)
}

func tokenFromHeader(r *http.Request) ([]byte, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, ErrNoHeader
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, errAuthSchema
	}
	return []byte(auth[7:]), nil
}

// ECDSASignHeader applies ECDSASign on a HTTP request.
// Specifically it sets a bearer token in the Authorization header.
func (c *Claims) ECDSASignHeader(r *http.Request, alg string, key *ecdsa.PrivateKey) error {
	token, err := c.ECDSASign(alg, key)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+string(token))
	return nil
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
	// ECDSAKey applies ECDSAAlgs and disables HMACAlgs when set.
	ECDSAKey *ecdsa.PublicKey
	// RSAKey applies RSAAlgs and disables HMACAlgs when set.
	RSAKey *rsa.PublicKey
	// Keys disables Secret, ECDSAKey and RSAKey when set.
	Keys *KeyRegister

	// HeaderBinding maps JWT claim names to HTTP header names.
	// All requests passed to Target have these headers set. In
	// case of failure the request is rejected with status code
	// 401 (Unauthorized) and a description.
	HeaderBinding map[string]string

	// ContextKey places the validated Claims in the context of
	// each respective request passed to Target when set. See
	// http.Request.Context and context.Context.Value.
	ContextKey string

	// When not nil, then Func is called after the JWT validation
	// succeeds and before any header bindings. Target is skipped
	// [request drop] when the return is false.
	// This feature may be used to further customise requests or
	// as a filter or as an extended http.HandlerFunc.
	Func func(http.ResponseWriter, *http.Request, *Claims) (pass bool)
}

// ServeHTTP honors the http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// verify claims
	var claims *Claims
	var err error
	if h.Keys != nil {
		claims, err = h.Keys.CheckHeader(r)
	} else if h.ECDSAKey == nil && h.RSAKey == nil {
		claims, err = HMACCheckHeader(r, h.Secret)
	} else {
		err = ErrAlgUnk
		if h.RSAKey != nil {
			claims, err = RSACheckHeader(r, h.RSAKey)
		}
		if err == ErrAlgUnk && h.ECDSAKey != nil {
			claims, err = ECDSACheckHeader(r, h.ECDSAKey)
		}
	}
	if err != nil {
		if err == ErrNoHeader {
			w.Header().Set("WWW-Authenticate", "Bearer")
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description=`+strconv.QuoteToASCII(err.Error()))
		}
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
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description=`+strconv.QuoteToASCII(msg))
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		r.Header.Set(headerName, s)
	}

	// place claims in request context
	if h.ContextKey != "" {
		r = r.WithContext(context.WithValue(r.Context(), h.ContextKey, claims))
	}

	h.Target.ServeHTTP(w, r)
}
