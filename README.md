[![API Documentation](https://godoc.org/github.com/pascaldekloe/jwt?status.svg)](https://godoc.org/github.com/pascaldekloe/jwt)
[![Build Status](https://circleci.com/gh/pascaldekloe/jwt.svg?style=svg)](https://circleci.com/gh/pascaldekloe/jwt)

## About

… a JSON Web Token (JWT) library for the Go programming language.

The API enforces secure use by design. Unsigned tokens are rejected.
No support for encrypted tokens either—use wire encryption instead.

* Feature complete
* No third party dependencies
* Full unit test coverage

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).


## Introduction

Tokens encapsulate signed statements called claims. A claim is JSON value,
identified by its name. The specification includes 7
[standardised claims](https://godoc.org/github.com/pascaldekloe/jwt#Registered).

```go
var claims jwt.Claims
claims.Subject = "alice@example.com"

now := time.Now().Round(time.Second)
claims.Issued = NewNumericTime(now)
claims.Expires = NewNumericTime(now.Add(10*time.Minute))

// issue a JWT
token, err := claims.EdDSASign(JWTPrivateKey)
```

Tokens consists of printable ASCII characters, e.g.
`eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJha3JpZWdlciIsInByZWZpeCI6IkRyLiJ9.RTOboYsLW7zXFJyXtIypOmXfuRGVT_FpDUTs2TOuK73qZKm56JcESfsl_etnBsl7W80TXE5l5qecrMizh3XYmw`.
Secured resources can use such tokens to determine access.

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

The following results were measured on an Intel i5-7500.

```
name                   time/op
ECDSA/sign-ES256-4     26.7µs ± 0%
ECDSA/sign-ES384-4     4.09ms ± 0%
ECDSA/sign-ES512-4     7.27ms ± 1%
ECDSA/check-ES256-4    80.8µs ± 1%
ECDSA/check-ES384-4    8.10ms ± 0%
ECDSA/check-ES512-4    14.1ms ± 0%
EdDSA/sign-EdDSA-4     50.8µs ± 1%
EdDSA/check-EdDSA-4     136µs ± 0%
HMAC/sign-HS256-4      2.02µs ± 1%
HMAC/sign-HS384-4      2.30µs ± 1%
HMAC/sign-HS512-4      2.34µs ± 1%
HMAC/check-HS256-4     4.05µs ± 0%
HMAC/check-HS384-4     4.40µs ± 0%
HMAC/check-HS512-4     4.51µs ± 0%
RSA/sign-1024-bit-4     314µs ± 0%
RSA/sign-2048-bit-4    1.47ms ± 0%
RSA/sign-4096-bit-4    8.22ms ± 0%
RSA/check-1024-bit-4   27.2µs ± 0%
RSA/check-2048-bit-4   62.2µs ± 0%
RSA/check-4096-bit-4    167µs ± 0%
```

EdDSA [Ed25519] produces small signatures and it performs well.


## Standard Compliance

* RFC 6750: “The OAuth 2.0 Authorization Framework: Bearer Token Usage”
* RFC 7468: “Textual Encodings of PKIX, PKCS, and CMS Structures”
* RFC 7515: “JSON Web Signature (JWS)”
* RFC 7517: “JSON Web Key (JWK)”
* RFC 7518: “JSON Web Algorithms (JWA)”
* RFC 7519: “JSON Web Token (JWT)”
* RFC 8037: “CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)”


[![JWT.io](https://jwt.io/img/badge.svg)](https://jwt.io/)
