package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
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

// ErrNoHeader signals an HTTP request without authorization.
var ErrNoHeader = errors.New("jwt: no HTTP authorization header")

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

// EdDSACheckHeader applies EdDSACheck on a HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func EdDSACheckHeader(r *http.Request, key ed25519.PublicKey) (*Claims, error) {
	token, err := tokenFromHeader(r)
	if err != nil {
		return nil, err
	}
	return EdDSACheck(token, key)
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
	h := r.Header["Authorization"]
	if h == nil {
		return nil, ErrNoHeader
	}

	// “Multiple message-header fields with the same field-name MAY be
	// present in a message if and only if the entire field-value for that
	//  header field is defined as a comma-separated list.”
	// — “Hypertext Transfer Protocol” RFC 2616, subsection 4.2
	auth := strings.Join(h, ", ")

	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return nil, errAuthSchema
	}
	return []byte(auth[len(prefix):]), nil
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

// EdDSASignHeader applies ECDSASign on a HTTP request.
// Specifically it sets a bearer token in the Authorization header.
func (c *Claims) EdDSASignHeader(r *http.Request, key ed25519.PrivateKey) error {
	token, err := c.EdDSASign(key)
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
// Requests are only passed to Target if the JWT checks out.
type Handler struct {
	// Target is the secured service.
	Target http.Handler

	// Keys defines the trusted credentials.
	Keys *KeyRegister

	// HeaderBinding maps JWT claim names to HTTP header names.
	// All requests passed to Target have these headers set. In
	// case of failure the request is rejected with status code
	// 401 (Unauthorized) and a description.
	HeaderBinding map[string]string

	// HeaderPrefix is an optional constraint for JWT claim binding.
	// Any client headers that match the prefix are removed from the
	// request. HeaderBinding entries that don't match the prefix
	// are ignored.
	HeaderPrefix string

	// ContextKey places the validated Claims in the context of
	// each respective request passed to Target when set. See
	// http.Request.Context and context.Context.Value.
	ContextKey interface{}

	// When not nil, then Func is called after the JWT validation
	// succeeds and before any header bindings. Target is skipped
	// [request drop] when the return is false.
	// This feature may be used to further customise requests or
	// as a filter or as an extended http.HandlerFunc.
	Func func(http.ResponseWriter, *http.Request, *Claims) (pass bool)

	// WriteError allows for custom error responses. When nil it defaults to http.Error.
	// The appropriate WWW-Authenticate header is already present on w.
	WriteError func(w http.ResponseWriter, error string, code int)
}

// ServeHTTP honors the http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// verify claims
	claims, err := h.Keys.CheckHeader(r)
	if err != nil {
		if err == ErrNoHeader {
			w.Header().Set("WWW-Authenticate", "Bearer")
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description=`+strconv.QuoteToASCII(err.Error()))
		}
		if h.WriteError != nil {
			h.WriteError(w, err.Error(), http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// verify time constraints
	if !claims.Valid(time.Now()) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="jwt: time constraints exceeded"`)
		if h.WriteError != nil {
			h.WriteError(w, "jwt: time constraints exceeded", http.StatusUnauthorized)
			return
		}
		http.Error(w, "jwt: time constraints exceeded", http.StatusUnauthorized)
		return
	}

	// filter request headers
	if h.HeaderPrefix != "" {
		for name := range r.Header {
			if strings.HasPrefix(name, h.HeaderPrefix) {
				delete(r.Header, name)
			}
		}
	}

	// apply the custom function when set
	if h.Func != nil && !h.Func(w, r, claims) {
		return
	}

	// claim propagation
	for claimName, headerName := range h.HeaderBinding {
		if !strings.HasPrefix(headerName, h.HeaderPrefix) {
			continue // silent ignore
		}

		s, ok := claims.String(claimName)
		if !ok {
			msg := "jwt: want string for claim " + claimName
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description=`+strconv.QuoteToASCII(msg))
			if h.WriteError != nil {
				h.WriteError(w, msg, http.StatusUnauthorized)
				return
			}
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		r.Header.Set(headerName, s)
	}

	// place claims in request context
	if h.ContextKey != nil {
		r = r.WithContext(context.WithValue(r.Context(), h.ContextKey, claims))
	}

	h.Target.ServeHTTP(w, r)
}