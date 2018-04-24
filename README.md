[![API Documentation](https://godoc.org/github.com/pascaldekloe/jwt?status.svg)](https://godoc.org/github.com/pascaldekloe/jwt)
[![Build Status](https://travis-ci.org/pascaldekloe/jwt.svg?branch=master)](https://travis-ci.org/pascaldekloe/jwt)
[![Build Report](https://cover.run/go/github.com/pascaldekloe/jwt.svg)](https://cover.run/go/github.com/pascaldekloe/jwt)

JSON Web Token (JWT) library for the Go programming language.

* Lightweight implementation
* No third party dependencies
* No support for (ECDSA) encryption

This is free and unencumbered software released into the
[public domain](http://creativecommons.org/publicdomain/zero/1.0).


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

[![JWT.io](http://jwt.io/img/badge.svg)](https://jwt.io/)
