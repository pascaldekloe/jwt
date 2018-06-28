[![API Documentation](https://godoc.org/github.com/pascaldekloe/jwt?status.svg)](https://godoc.org/github.com/pascaldekloe/jwt)
[![Build Status](https://travis-ci.org/pascaldekloe/jwt.svg?branch=master)](https://travis-ci.org/pascaldekloe/jwt)
[![Test Coverage](https://cover.run/go/github.com/pascaldekloe/jwt.svg?style=flat&tag=golang-1.10)](https://cover.run/go?tag=golang-1.10&repo=github.com%2Fpascaldekloe%2Fjwt)

A JSON Web Token (JWT) library for the Go programming language.

The API enforces secure use by design. Unsigned tokens are
[rejected](https://godoc.org/github.com/pascaldekloe/jwt#ErrUnsecured)
and there is no support for (ECDSA) encryption—use wire encryption instead.
With less than 500 lines of code and no third party dependencies, the
implementation maintains full unit test coverage.

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).


## Get Started

The package comes with functions to verify 
[[HMACCheck](https://godoc.org/github.com/pascaldekloe/jwt#HMACCheck),
[RSACheck](https://godoc.org/github.com/pascaldekloe/jwt#RSACheck)] 
and issue 
[[HMACSign](https://godoc.org/github.com/pascaldekloe/jwt#Claims.HMACSign),
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

Optionally one can use the claims object in the service handlers as shown in the
[“direct” example](https://godoc.org/github.com/pascaldekloe/jwt#example-Handler--Direct).


### Performance on a Mac Pro (late 2013)

```
BenchmarkHMACSign/HS256-12         	  500000	      3398 ns/op
BenchmarkHMACSign/HS384-12         	  500000	      3940 ns/op
BenchmarkHMACSign/HS512-12         	  300000	      4032 ns/op
BenchmarkHMACCheck/HS256-12        	  200000	      6853 ns/op
BenchmarkHMACCheck/HS384-12        	  200000	      7495 ns/op
BenchmarkHMACCheck/HS512-12        	  200000	      7603 ns/op
BenchmarkRSASign/1024-bit-12       	    3000	    422137 ns/op
BenchmarkRSASign/2048-bit-12       	    1000	   2094975 ns/op
BenchmarkRSASign/4096-bit-12       	     100	  12902447 ns/op
BenchmarkRSACheck/1024-bit-12      	   50000	     34042 ns/op
BenchmarkRSACheck/2048-bit-12      	   20000	     73650 ns/op
BenchmarkRSACheck/4096-bit-12      	   10000	    203782 ns/op
```

[![JWT.io](https://jwt.io/img/badge.svg)](https://jwt.io/)
