[![API Documentation](https://godoc.org/github.com/pascaldekloe/jwt?status.svg)](https://godoc.org/github.com/pascaldekloe/jwt)
[![Build Status](https://travis-ci.org/pascaldekloe/jwt.svg?branch=master)](https://travis-ci.org/pascaldekloe/jwt)

A JSON Web Token (JWT) library for the Go programming language.

The API enforces secure use by design. Unsigned tokens are
[rejected](https://godoc.org/github.com/pascaldekloe/jwt#ErrUnsecured)
and there is no support for encryption—use wire encryption instead.
With about 700 lines of code and no third party dependencies, the
implementation maintains full unit test coverage.

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).


## Get Started

The package comes with functions to verify 
[[ECDSACheck](https://godoc.org/github.com/pascaldekloe/jwt#ECDSACheck),
[HMACCheck](https://godoc.org/github.com/pascaldekloe/jwt#HMACCheck),
[RSACheck](https://godoc.org/github.com/pascaldekloe/jwt#RSACheck)] 
and issue 
[[ECDSASign](https://godoc.org/github.com/pascaldekloe/jwt#Claims.ECDSASign),
[HMACSign](https://godoc.org/github.com/pascaldekloe/jwt#Claims.HMACSign),
[RSASign](https://godoc.org/github.com/pascaldekloe/jwt#Claims.RSASign)]
claims.

For server side security an `http.Handler` based setup can be used as well.
The following example enforces the subject, formatted name and roles to be
present as a valid JWT in all requests towards the `MyAPI` handler.

```go
// configuration demo
http.DefaultServeMux.Handle("/api/v1", &jwt.Handler{
	Target: MyAPI, // the protected service multiplexer
	RSAKey: JWTPublicKey,

	// map some claims to HTTP headers
	HeaderBinding: map[string]string{
		"sub": "X-Verified-User", // registered [standard] claim
		"fn":  "X-Verified-Name", // private [custom] claim
	},

	// customise further with RBAC
	Func: func(w http.ResponseWriter, req *http.Request, claims *jwt.Claims) (pass bool) {
		log.Printf("got a valid JWT %q for %q", claims.ID, claims.Audience)

		// map role enumeration
		s, ok := claims.String("roles")
		if !ok {
			http.Error(w, "jwt: want roles claim as a string", http.StatusForbidden)
			return false
		}
		req.Header["X-Verified-Roles"] = strings.Fields(s)

		return true
	},
})
```

When all applicable JWT claims are mapped to HTTP request headers, then the
service logic can stay free of verification code plus easier unit testing.

```go
// Greeting is a standard HTTP handler fuction.
func Greeting(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Hello %s!\nYou are authorized as %s.\n",
		req.Header.Get("X-Verified-Name"), req.Header.Get("X-Verified-User"))
}
```

Optionally one can use the claims object from the HTTP request as shown in the
[“context” example](https://godoc.org/github.com/pascaldekloe/jwt#example-Handler--Context).


### Performance on a Mac Pro (late 2013)

```
ECDSA/sign-ES256-12    37.7µs ± 0%
ECDSA/sign-ES384-12    4.26ms ± 0%
ECDSA/sign-ES512-12    8.03ms ± 0%
ECDSA/check-ES256-12    106µs ± 0%
ECDSA/check-ES384-12   8.36ms ± 0%
ECDSA/check-ES512-12   15.7ms ± 0%
HMAC/sign-HS256-12     3.47µs ± 0%
HMAC/sign-HS384-12     3.97µs ± 0%
HMAC/sign-HS512-12     4.03µs ± 0%
HMAC/check-HS256-12    6.97µs ± 0%
HMAC/check-HS384-12    7.96µs ± 4%
HMAC/check-HS512-12    7.81µs ± 0%
RSA/sign-1024-bit-12    418µs ± 0%
RSA/sign-2048-bit-12   2.09ms ± 0%
RSA/sign-4096-bit-12   12.9ms ± 0%
RSA/check-1024-bit-12  33.2µs ± 0%
RSA/check-2048-bit-12  73.4µs ± 0%
RSA/check-4096-bit-12   201µs ± 0%
```

[![JWT.io](https://jwt.io/img/badge.svg)](https://jwt.io/)
