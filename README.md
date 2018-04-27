[![API Documentation](https://godoc.org/github.com/pascaldekloe/jwt?status.svg)](https://godoc.org/github.com/pascaldekloe/jwt)
[![Build Status](https://travis-ci.org/pascaldekloe/jwt.svg?branch=master)](https://travis-ci.org/pascaldekloe/jwt)
[![Build Report](https://cover.run/go/github.com/pascaldekloe/jwt.svg)](https://cover.run/go/github.com/pascaldekloe/jwt)

A JSON Web Token (JWT) library for the Go programming language.

* Lightweight implementation [less than 500 lines]
* Full unit test coverage
* No third party dependencies
* No support for (ECDSA) encryption

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).


## Get Started

The package comes with *check* and *sign* functions to verify and issue claims.
For server side security an `http.Handler` based setup can be used as follows.

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
BenchmarkHMACSign/HS256-12         	  500000	      3497 ns/op
BenchmarkHMACSign/HS384-12         	  300000	      4090 ns/op
BenchmarkHMACSign/HS512-12         	  300000	      4192 ns/op
BenchmarkHMACCheck/HS256-12        	  200000	      7088 ns/op
BenchmarkHMACCheck/HS384-12        	  200000	      7807 ns/op
BenchmarkHMACCheck/HS512-12        	  200000	      7939 ns/op
BenchmarkRSASign/1024-bit-12       	    3000	    569604 ns/op
BenchmarkRSASign/2048-bit-12       	     500	   2569394 ns/op
BenchmarkRSASign/4096-bit-12       	     100	  14744651 ns/op
BenchmarkRSACheck/1024-bit-12      	   50000	     33513 ns/op
BenchmarkRSACheck/2048-bit-12      	   20000	     73952 ns/op
BenchmarkRSACheck/4096-bit-12      	   10000	    204450 ns/op
```

[![JWT.io](https://jwt.io/img/badge.svg)](https://jwt.io/)
