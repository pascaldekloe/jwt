package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

var testKeyRSA = mustParseRSAKey(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA8NBRypbuyT1o2p7Ze94kmZTrwu2TsqZ1u7BOcY97xn6cc7/e
c9aZI+S4Ure57XNvKQAZlULWjWhEfY8vhP1m2hDzVCV0DnNRCPmMJxx212b2iTmA
1IsMmRYFHOYgVVUdx5QzS1xIQMZgyLP++CBkYJXZZCC1MBqyW93BkBcNzt0+70ZT
mMpXOYKoq/pFcxVMllKY41JCcDqpKcJnSmWyS+DQX5X4CcNecXxCMoL7WGeMVrng
7NTFJmv4Iyh19/WRERqQUqlPPQoWd0Wrw/Ih+p38PlxvdxxcGIgG8gZC1eZ441MR
4KeHEnx7nQ08TtzdsTULYlx3kM173h1yI+HuBwIDAQABAoIBAQCyX5w2E9aL+ZDR
Xxh5R/KUUFrR6Giey+4pOE7ijwV/4gjBND3yT+LfU2u02aI+4GJWXFyW0wtZcwJI
fucT+x9UJ3oVuihdC83ad/34en0M0JeMzas/xD9wpX7kCRGqI4ILcxsLly9ty4Ol
Jq6V3Gh9ooGESTXsi9nRclEOCgWQU6F8BeDGbI19aqkFi67wZqvOYrlUXfznRwQQ
iaffaeh+wH5qp79dd+MoSPJLmhuhNH6Q/T70tVqTvlslufcro1/7YYuq9X2/IO+u
O1Nd1/nyT46xYQ16HqLdH2KPN2jsmbWFCMM4leTbyk18ldDnU3LG7BMwwoW7vemE
gU8KuX4BAoGBAP4zMVT+M1421fXUTyxK1ViQprdqT5zksFwK0cMdy1upE0EFqUrr
TtN5mao+7rGFp7R/0xuVSwYs+LX7jsrRPXn5JgB2JdPg9UakdKkULAfGVCLJouXm
/32C9YlFuqPjJWxr5Ndb1aqvPNfIvsfmys1O+GJ39x9R+iFezvuKN2BvAoGBAPKE
3E9fSWjXg9N+y2QazeU6wJjJYhIGtceuTwPPW1n3IfOzgB1QHXZhH7YM07OoI2jF
NFBM99ygjdfRbKCosEQoUQCF78avHYJJDhdPhjAWiaIZg7X4gfgWqEMJ0SWXyCAM
cxQ0XEC0AHocWNipWv8zVFEC62K3omMXS/9leefpAoGAB/eGxkkpRvyk/A1pZdP6
l8oAz6LPV/V66YeVR245n2fPKKyKv8RcNhiLjmBmjr3HocqXzTeCoHDsYpe9w/GG
4bnDTSRmzxsv1MT2uw3cy2mV3XlAV8BDpaVjGKhMzzIhTCKdi3pfWfggCgtKn21G
UeT1t/BWmG6zTjRwfEW6spUCgYAUsXF69E53O6xr523DZOYcoR696rELiLcKCr2D
PbY1vviOqspLtgJNj4v9JKsLsVUUI3+LOoYLtUdlGuGB8+LWbfo7aTJEabzC2Sjy
pD526/Vid3rdlA7C9Gv3DGdkJcdVtLo9Bxq4CqPfx3ttQUYacG7JWs5q5fBdNCev
6yCzwQKBgHZRiC82Bzd10OgIL4WadlNphmMnGgROgNhwBu2bd5loPc+26omBAVtC
mQ9Ug7u6QOshlvxmqrgRFlWkLAwozqvS6RC4yru8FRqYnmtW7QgxO1pOj9VEzHSw
iugbqlkWvaTnn5JZoHZ+60PZc8Z4UJvzi0/h9ksnWhp5l6u1KBmc
-----END RSA PRIVATE KEY-----`)

func TestNumericTimeMapping(t *testing.T) {
	if got := NewNumericTime(time.Time{}); got != nil {
		t.Errorf("NewNumericTime from zero value got %f, want nil", *got)
	}
	if got := (*NumericTime)(nil).Time(); !got.IsZero() {
		t.Errorf("nil NumericTime got %s, want zero value", got)
	}
	if got := (*NumericTime)(nil).String(); got != "" {
		t.Errorf("nil NumericTime String got %q", got)
	}

	n := NumericTime(1234567890.12)
	d := time.Date(2009, 2, 13, 23, 31, 30, 12E7, time.UTC)

	if got := NewNumericTime(d); got == nil {
		t.Error("NewNumericTime from non-zero value got nil")
	} else if *got != n {
		t.Errorf("NewNumericTime got %f, want %f", *got, n)
	}
	if got := n.Time(); !got.Equal(d) {
		t.Errorf("Time got %s, want %s", got, d)
	}

	iso := "2009-02-13T23:31:30.12Z"
	if got := n.String(); got != iso {
		t.Errorf("String got %q, want %q", got, iso)
	}
}

func TestClaimsValid(t *testing.T) {
	c := new(Claims)
	if !c.Valid(time.Time{}) {
		t.Error("invalidated claims without time limits for zero")
	}
	if !c.Valid(time.Now()) {
		t.Error("invalidated claims without time limits")
	}

	now := time.Now()
	c.Registered.NotBefore = NewNumericTime(now)
	c.Registered.Expires = NewNumericTime(now.Add(time.Minute))

	if c.Valid(time.Time{}) {
		t.Error("validated claims with time limits for zero time")
	}
	if c.Valid(c.Registered.NotBefore.Time().Add(-time.Second)) {
		t.Error("validated claims before time limit")
	}
	if !c.Valid(c.Registered.NotBefore.Time()) {
		t.Error("invalidated claims on time limit start")
	}
	if !c.Valid(c.Registered.NotBefore.Time().Add(time.Second)) {
		t.Error("invalidated claims within time limit")
	}
	if c.Valid(c.Registered.Expires.Time()) {
		t.Error("validated claims on time limit end")
	}
	if c.Valid(c.Registered.Expires.Time().Add(time.Second)) {
		t.Error("validated claims after time limit end")
	}
}

func mustParseRSAKey(s string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		panic("invalid PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}
