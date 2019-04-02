[![API Documentation](https://godoc.org/github.com/pascaldekloe/jwt?status.svg)](https://godoc.org/github.com/pascaldekloe/jwt)
[![Build Status](https://travis-ci.org/pascaldekloe/jwt.svg?branch=master)](https://travis-ci.org/pascaldekloe/jwt)

## About

A JSON Web Token (JWT) library for the Go programming language.

The API enforces secure use by design. Unsigned tokens are rejected
and no support for encrypted tokens—use wire encryption instead.

* Compact implementation
* No third party dependencies
* Full unit test coverage
* Feature complete

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).


## Introduction

Tokens encapsulate signed claims in the form of a printable ASCII sequence like
“eyJhbGciOiJFUzUxMiJ9.eyJzdWIiOiJha3JpZWdlciIsInByZWZpeCI6IkRyLiJ9.APhisjBsvFDWLojTWUP7uyEiilIOU4KYVEgqFr5GdJbd5ucuejztFUvzRZq8njo2s0jLqwMN6H0IhG9YHDMRKTgQAbEbOT_13tN6Xs4sTtxefuf_jlJTfTLtg9_2A22iGYgSDBTzWpunC-Ofuq4XegptS2NuC6XGTFu41DbQX6EmEb-7”.

```go
var claims jwt.Claims
claims.Issuer = "demo"
claims.Audiences = []string{"README", "API"}
// issue a JWT
token, err := claims.ECDSASign(jwt.ES256, JWTPrivateKey)
```

Secured resources may use tokens to determine access.

```go
// verify a JWT
claims, err := jwt.ECDSACheck(token, JWTPublicKey)
if err != nil {
	log.Print("credentials denied: ", err)
	return
}
if !claims.Valid(time.Now()) {
	log.Print("credential time constraints exceeded")
	return
}
log.Print("hello ", claims.Subject)
```

JWT allows for security enforcement without the need for a central decision
point—that is, the enforcement point can make decisions by it self based on
signed claims. Commonly agents receive a JWT uppon authentication/login and
then they provide that token with each request to a secured resource/API.

Token access is "eyes only". Time constraints may be used to reduce risk.
It is recommended to include (and enforce) more details about the client to
prevent use of hijacked tokens, e.g, the TLS client fingerprint.


# High-level API

Server-side security can be applied with a standard `http.Handler` setup.
The following example denies requests to `MyAPI` when the JWT is not valid,
or when the JWT does not have a subject, formatted name or roles present.

```go
// define trusted credentials
var keys jwt.KeyRegister
n, err := keys.LoadPEM(text, nil)
if err != nil {
	log.Fatal(err)
}
log.Print("setup with ", n, " JWT keys")

http.Handle("/api/v1", &jwt.Handler{
	Target: MyAPI, // protected HTTP handler
	Keys: keys,

	// map two claims to HTTP headers
	HeaderBinding: map[string]string{
		"sub": "X-Verified-User", // registered [standard] claim
		"fn":  "X-Verified-Name", // private [custom] claim
	},

	// customise with RBAC
	Func: func(w http.ResponseWriter, req *http.Request, claims *jwt.Claims) (pass bool) {
		log.Printf("got a valid JWT %q for %q", claims.ID, claims.Audiences)

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

Alternatively, claims can be propagated through the
[request context](https://godoc.org/github.com/pascaldekloe/jwt#example-Handler--Context).


### Performance

Choose your algorithm wisely. The following results were measured on a 3.5 GHz
Xeon E5-1650 v2 (Ivy Bridge-EP).

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
