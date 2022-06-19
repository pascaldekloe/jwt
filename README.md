[![API Documentation](https://godoc.org/github.com/pascaldekloe/jwt?status.svg)](https://godoc.org/github.com/pascaldekloe/jwt)
[![Build Status](https://github.com/pascaldekloe/jwt/actions/workflows/go.yml/badge.svg)](https://github.com/pascaldekloe/jwt/actions/workflows/go.yml)

## About

… a JSON Web Token (JWT) library for the Go programming language.

* Feature complete
* Full test coverage
* Dependency free
* Key [management](https://godoc.org/github.com/pascaldekloe/jwt#KeyRegister)

The API enforces secure use by design. Unsigned tokens are [rejected](https://godoc.org/github.com/pascaldekloe/jwt#ErrUnsecured).
No support for encrypted tokens either—use wire encryption instead.

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).


## Introduction

Tokens encapsulate signed statements called claims. A claim is a named JSON
value. Applications using JWTs should define which specific claims they use and
when they are required or optional.

```go
var claims jwt.Claims
claims.Subject = "alice"
claims.Issued  = jwt.NewNumericTime(time.Now().Round(time.Second))
claims.Set     = map[string]interface{}{"email_verified": false}
// issue a JWT
token, err := claims.EdDSASign(JWTPrivateKey)
```

Tokens consists of printable ASCII characters, e.g.,
`eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJha3JpZWdlciIsInByZWZpeCI6IkRyLiJ9.RTOboYsLW7zXFJyXtIypOmXfuRGVT_FpDUTs2TOuK73qZKm56JcESfsl_etnBsl7W80TXE5l5qecrMizh3XYmw`.
Secured resources can use such tokens to determine the respective permissions.
Note how the verification process is self-contained with just a public key.

```go
// verify a JWT
claims, err := jwt.EdDSACheck(token, JWTPublicKey)
if err != nil {
	log.Print("credentials rejected: ", err)
	return
}
err = claims.AcceptTemporal(time.Now(), time.Second)
if err != nil {
	log.Print("credential constraints violated: ", err)
	return
}

// ready for use
log.Print("hello ", claims.Subject)
if verified, _ := claims.Set["email_verified"].(bool); !verified {
	log.Print("e-mail confirmation pending")
}
```

Commonly, agents receive a JWT uppon authentication/login. Then, that token is
included with requests to the secured resources, as a proof of authority. Token
access is “eyes only” in such scenario. Include and enforce more context detail
with claims to further reduce risk. E.g., a session identifier or a fingerprint
of the client's TLS key can prevent usage of any hijacked tokens.


## High-Level API

Server-side security can be applied with a standard `http.Handler` setup.
The following example denies requests to `MyAPI` when the JWT is not valid,
or when the JWT is missing either the subject, formatted name or roles claim.

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
	Keys:   &keys,

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
service logic can stay free of verification code, plus easier unit testing.

```go
// Greeting is a standard HTTP handler fuction.
func Greeting(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Hello %s!\n", req.Header.Get("X-Verified-Name"))
	fmt.Fprintf(w, "You are authorized as %s.\n", req.Header.Get("X-Verified-User"))
}
```

The validated [Claims](https://godoc.org/github.com/pascaldekloe/jwt#Claims)
object may also be exposed through the
[request context](https://godoc.org/github.com/pascaldekloe/jwt#example-Handler--Context).


## Performance

The following results were measured with Go 1.19-beta1 on an Apple M1.

```
name                      time/op
ECDSA/sign-ES256-8        19.8µs ± 0%
ECDSA/sign-ES384-8         196µs ± 0%
ECDSA/check-ES256-8       58.7µs ± 0%
ECDSA/check-ES384-8        632µs ± 0%
EdDSA/sign-EdDSA-8        24.9µs ± 0%
EdDSA/check-EdDSA-8       54.0µs ± 0%
HMAC/sign-HS256-8          664ns ± 1%
HMAC/sign-HS256-reuse-8    461ns ± 0%
HMAC/sign-HS384-8         2.60µs ± 0%
HMAC/sign-HS384-reuse-8   1.40µs ± 0%
HMAC/sign-HS512-8         2.61µs ± 0%
HMAC/sign-HS512-reuse-8   1.41µs ± 0%
HMAC/check-HS256-8        1.81µs ± 1%
HMAC/check-HS256-reuse-8  1.61µs ± 1%
HMAC/check-HS384-8        3.75µs ± 0%
HMAC/check-HS384-reuse-8  2.54µs ± 1%
HMAC/check-HS512-8        3.76µs ± 0%
HMAC/check-HS512-reuse-8  2.56µs ± 0%
RSA/sign-1024-bit-8        226µs ± 1%
RSA/sign-2048-bit-8       1.10ms ± 2%
RSA/sign-4096-bit-8       6.03ms ± 3%
RSA/check-1024-bit-8      13.4µs ± 0%
RSA/check-2048-bit-8      30.7µs ± 1%
RSA/check-4096-bit-8      90.3µs ± 1%
```

EdDSA [Ed25519] produces small signatures and it performs well.


## Standard Compliance

* RFC 2617: “HTTP Authentication”
* RFC 6750: “The OAuth 2.0 Authorization Framework: Bearer Token Usage”
* RFC 7468: “Textual Encodings of PKIX, PKCS, and CMS Structures”
* RFC 7515: “JSON Web Signature (JWS)”
* RFC 7517: “JSON Web Key (JWK)”
* RFC 7518: “JSON Web Algorithms (JWA)”
* RFC 7519: “JSON Web Token (JWT)”
* RFC 8037: “CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)”


[![JWT.io](https://jwt.io/img/badge.svg)](https://jwt.io/)
