[![API Documentation](https://godoc.org/github.com/pascaldekloe/jwt?status.svg)](https://godoc.org/github.com/pascaldekloe/jwt)
[![Build Status](https://circleci.com/gh/pascaldekloe/jwt.svg?style=svg)](https://circleci.com/gh/pascaldekloe/jwt)

## About

… a JSON Web Token (JWT) library for the Go programming language.

The API enforces secure use by design. Unsigned tokens are rejected
and no support for encrypted tokens—use wire encryption instead.

* Compact implementation
* No third party dependencies
* Full unit test coverage
* Feature complete

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).


## Introduction

Tokens encapsulate signed statements called claims. A claim is JSON value,
identified by its name. The specification includes 7
[standardised claims](https://godoc.org/github.com/pascaldekloe/jwt#Registered).
Tokens consists of printable ASCII characters, e.g.
`eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJha3JpZWdlciIsInByZWZpeCI6IkRyLiJ9.RTOboYsLW7zXFJyXtIypOmXfuRGVT_FpDUTs2TOuK73qZKm56JcESfsl_etnBsl7W80TXE5l5qecrMizh3XYmw`.

```go
var claims jwt.Claims
claims.Subject = "alice@example.com"

now := time.Now().Round(time.Second)
claims.Issued = NewNumericTime(now)
claims.Expires = NewNumericTime(now.Add(10*time.Minute))

// issue a JWT
token, err := claims.EdDSASign(JWTPrivateKey)
```

Secured resources can use tokens to determine access.

```go
// verify a JWT
claims, err := jwt.EdDSACheck(token, JWTPublicKey)
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

Commonly, agents receive a JWT uppon authentication/login. Then, that token is
supplied with each request to a secured resource/API, as a proof of authority.
Token access is "eyes only". Time constraints may be used to reduce risk. It is
recommended to include (and enforce) more details about the client, like a TLS
client fingerprint, to prevent use of hijacked tokens.


## High-Level API

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
	Keys:   keys,

	// map two claims to HTTP headers
	HeaderPrefix: "X-Verified-",
	HeaderBinding: map[string]string{
		"sub": "X-Verified-User", // registered [standard] claim
		"fn":  "X-Verified-Name", // private [custom] claim
	},

	// map another claim with custom logic
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

The validated [Claims](https://godoc.org/github.com/pascaldekloe/jwt#Claims)
can also be propagated through the
[request context](https://godoc.org/github.com/pascaldekloe/jwt#example-Handler--Context).


## Performance

The following results were measured on a 3.5 GHz Xeon E5-1650 v2 (Ivy Bridge-EP).

```
name                    time/op
ECDSA/sign-ES256-12     37.9µs ± 0%
ECDSA/sign-ES384-12     4.53ms ± 1%
ECDSA/sign-ES512-12     8.16ms ± 1%
ECDSA/check-ES256-12     105µs ± 1%
ECDSA/check-ES384-12    8.83ms ± 0%
ECDSA/check-ES512-12    16.0ms ± 1%
EdDSA/sign-Ed25519-12   60.0µs ± 1%
EdDSA/check-Ed25519-12   153µs ± 0%
HMAC/sign-HS256-12      3.29µs ± 1%
HMAC/sign-HS384-12      3.87µs ± 1%
HMAC/sign-HS512-12      3.91µs ± 0%
HMAC/check-HS256-12     6.74µs ± 0%
HMAC/check-HS384-12     7.36µs ± 0%
HMAC/check-HS512-12     7.55µs ± 1%
RSA/sign-1024-bit-12     427µs ± 1%
RSA/sign-2048-bit-12    2.12ms ± 1%
RSA/sign-4096-bit-12    12.9ms ± 0%
RSA/check-1024-bit-12   34.6µs ± 0%
RSA/check-2048-bit-12   75.9µs ± 0%
RSA/check-4096-bit-12    206µs ± 1%
```

EdDSA [Ed25519] produces small signatures and it performs well, especially on
more modern hardware.


## Standard Compliance

* RFC 7468: “Textual Encodings of PKIX, PKCS, and CMS Structures”
* RFC 7515: “JSON Web Signature (JWS)”
* RFC 7517: “JSON Web Key (JWK)”
* RFC 7518: “JSON Web Algorithms (JWA)”
* RFC 7519: “JSON Web Token (JWT)”
* RFC 8037: “CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)”


[![JWT.io](https://jwt.io/img/badge.svg)](https://jwt.io/)
