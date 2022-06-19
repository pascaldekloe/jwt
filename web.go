package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
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

var errNotBearer = errors.New("jwt: not HTTP Bearer scheme")

// ECDSACheckHeader applies ECDSACheck on an HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func ECDSACheckHeader(r *http.Request, key *ecdsa.PublicKey) (*Claims, error) {
	token, err := BearerToken(r.Header)
	if err != nil {
		return nil, err
	}
	return ECDSACheck([]byte(token), key)
}

// EdDSACheckHeader applies EdDSACheck on an HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func EdDSACheckHeader(r *http.Request, key ed25519.PublicKey) (*Claims, error) {
	token, err := BearerToken(r.Header)
	if err != nil {
		return nil, err
	}
	return EdDSACheck([]byte(token), key)
}

// HMACCheckHeader applies HMACCheck on an HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func HMACCheckHeader(r *http.Request, secret []byte) (*Claims, error) {
	token, err := BearerToken(r.Header)
	if err != nil {
		return nil, err
	}
	return HMACCheck([]byte(token), secret)
}

// CheckHeader applies Check on an HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func (h *HMAC) CheckHeader(r *http.Request) (*Claims, error) {
	token, err := BearerToken(r.Header)
	if err != nil {
		return nil, err
	}
	return h.Check([]byte(token))
}

// RSACheckHeader applies RSACheck on an HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func RSACheckHeader(r *http.Request, key *rsa.PublicKey) (*Claims, error) {
	token, err := BearerToken(r.Header)
	if err != nil {
		return nil, err
	}
	return RSACheck([]byte(token), key)
}

// CheckHeader applies KeyRegister.Check on an HTTP request.
// Specifically it looks for a bearer token in the Authorization header.
func (keys *KeyRegister) CheckHeader(r *http.Request) (*Claims, error) {
	token, err := BearerToken(r.Header)
	if err != nil {
		return nil, err
	}
	return keys.Check([]byte(token))
}

// Bearer extracts the token from an HTTP header.
func BearerToken(h http.Header) (token string, err error) {
	v := h.Values("Authorization")
	if len(v) == 0 {
		return "", ErrNoHeader
	}
	// “It MUST be possible to combine the multiple header fields into one
	// "field-name: field-value" pair, without changing the semantics of the
	// message, by appending each subsequent field-value to the first, each
	// separated by a comma.”
	// — “Hypertext Transfer Protocol” RFC 2616, subsection 4.2
	s := strings.Join(v, ", ")

	const prefix = "Bearer "
	// The scheme is case-insensitive 🤦 as per RFC 2617, subsection 1.2.
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", errNotBearer
	}
	return s[len(prefix):], nil
}

// ECDSASignHeader applies ECDSASign on an HTTP request.
// Specifically it sets a bearer token in the Authorization header.
func (c *Claims) ECDSASignHeader(r *http.Request, alg string, key *ecdsa.PrivateKey) error {
	token, err := c.ECDSASign(alg, key)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+string(token))
	return nil
}

// EdDSASignHeader applies ECDSASign on an HTTP request.
// Specifically it sets a bearer token in the Authorization header.
func (c *Claims) EdDSASignHeader(r *http.Request, key ed25519.PrivateKey) error {
	token, err := c.EdDSASign(key)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+string(token))
	return nil
}

// HMACSignHeader applies HMACSign on an HTTP request.
// Specifically it sets a bearer token in the Authorization header.
func (c *Claims) HMACSignHeader(r *http.Request, alg string, secret []byte) error {
	token, err := c.HMACSign(alg, secret)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+string(token))
	return nil
}

// SignHeader applies Sign on an HTTP request.
// Specifically it sets a bearer token in the Authorization header.
func (h *HMAC) SignHeader(c *Claims, r *http.Request) error {
	token, err := h.Sign(c)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+string(token))
	return nil
}

// RSASignHeader applies RSASign on an HTTP request.
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
	// request.
	HeaderPrefix string

	// ContextKey places the validated Claims in the context of
	// each respective request passed to Target when set. See
	// http.Request.Context and context.Context.Value.
	ContextKey interface{}

	// TemporalLeeway controls the tolerance with time constraints.
	TemporalLeeway time.Duration

	// When not nil, then Func is called after the JWT validation
	// succeeds and before any header bindings. Target is skipped
	// [request drop] when the return is false.
	// This feature may be used to further customise requests or
	// as a filter or as an extended http.HandlerFunc.
	Func func(http.ResponseWriter, *http.Request, *Claims) (pass bool)

	// Error sends a custom response. Nil defaults to http.Error.
	// The appropriate WWW-Authenticate value is already present.
	Error func(w http.ResponseWriter, error string, statusCode int)
}

func (h *Handler) error(w http.ResponseWriter, error string, statusCode int) {
	if h.Error != nil {
		h.Error(w, error, statusCode)
	} else {
		http.Error(w, error, statusCode)
	}
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
		h.error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// verify time constraints
	err = claims.AcceptTemporal(time.Now(), h.TemporalLeeway)
	if err != nil {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token", error_description=%q`, err))
		h.error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// filter request headers
	headerPrefix := http.CanonicalHeaderKey(h.HeaderPrefix)
	if headerPrefix != "" {
		for name := range r.Header {
			if strings.HasPrefix(name, headerPrefix) {
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
		headerName = http.CanonicalHeaderKey(headerName)
		if !strings.HasPrefix(headerName, headerPrefix) {
			h.error(w, "jwt: prefix mismatch in header binding", http.StatusInternalServerError)
			return
		}

		s, ok := claims.String(claimName)
		if !ok {
			msg := "jwt: want string for claim " + claimName
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description=`+strconv.QuoteToASCII(msg))
			h.error(w, msg, http.StatusUnauthorized)
			return
		}
		r.Header[headerName] = []string{s}
	}

	// place claims in request context
	if h.ContextKey != nil {
		r = r.WithContext(context.WithValue(r.Context(), h.ContextKey, claims))
	}

	h.Target.ServeHTTP(w, r)
}
