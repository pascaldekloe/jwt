[![API Documentation](https://godoc.org/github.com/pascaldekloe/jwt?status.svg)](https://godoc.org/github.com/pascaldekloe/jwt)
[![Build Status](https://travis-ci.org/pascaldekloe/jwt.svg?branch=master)](https://travis-ci.org/pascaldekloe/jwt)

A JSON Web Token (JWT) library for the Go programming language.

The API enforces secure use by design. Unsigned tokens are
[rejected](https://godoc.org/github.com/pascaldekloe/jwt#ErrUnsecured)
and there is no support for encryption—use wire encryption instead.

* No third party dependencies
* Full unit test coverage

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).


## Get Started

The package comes with functions to verify and issue claims.

```go
// create a JWT
var claims jwt.Claims
claims.Issuer = "demo"
token, err := claims.HMACSign(jwt.HS256, []byte("guest"))
```

The register helps with key migrations and fallback scenarios.

```go
var keys jwt.KeyRegister
keyCount, err := keys.LoadPEM(text, nil)
if err != nil {
	log.Fatal("JWT key import: ", err)
}
log.Print(keyCount, " JWT key(s) ready")
```

```go
// use a JWT
claims, err := keys.Check(token)
if err != nil {
	log.Print("credentials denied")
	return
}
if !claims.Valid(time.Now()) {
	log.Print("time constraints exceeded")
	return
}
log.Print("hello ", claims.Audiences)
```

For server side security an `http.Handler` based setup can be used as well.
The following example enforces the subject, formatted name and roles to be
present as a valid JWT in all requests towards the `MyAPI` handler.

```go
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
name                   time/op
ECDSA/sign-ES256-12    37.3µs ± 0%
ECDSA/sign-ES384-12    4.23ms ± 0%
ECDSA/sign-ES512-12    7.70ms ± 0%
ECDSA/check-ES256-12    105µs ± 1%
ECDSA/check-ES384-12   8.25ms ± 0%
ECDSA/check-ES512-12   14.7ms ± 0%
HMAC/sign-HS256-12     3.29µs ± 0%
HMAC/sign-HS384-12     3.83µs ± 0%
HMAC/sign-HS512-12     3.90µs ± 0%
HMAC/check-HS256-12    6.55µs ± 0%
HMAC/check-HS384-12    7.07µs ± 0%
HMAC/check-HS512-12    7.27µs ± 0%
RSA/sign-1024-bit-12    422µs ± 0%
RSA/sign-2048-bit-12   2.11ms ± 0%
RSA/sign-4096-bit-12   12.9ms ± 0%
RSA/check-1024-bit-12  33.6µs ± 0%
RSA/check-2048-bit-12  74.4µs ± 0%
RSA/check-4096-bit-12   203µs ± 0%
```

[![JWT.io](https://jwt.io/img/badge.svg)](https://jwt.io/)
