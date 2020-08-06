package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

var testKeyEC256 = mustParseECKey(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBOm12aaXvqSzysOSGV2yL/xKY3kCtaOfAPY1KQN2sTJoAoGCCqGSM49
AwEHoUQDQgAEX0iTLAcGqlWeGIRtIk0G2PRgpf/6gLxOTyMAdriP4NLRkuu+9Idt
y3qmEizRC0N81j84E213/LuqLqnsrgfyiw==
-----END EC PRIVATE KEY-----`)

var testKeyEC384 = mustParseECKey(`-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBluSyfK9BEPc9y944ZLahd4xHRVse64iCeEC5gBQ4UM1961bsEthUC
NKXyTGTBuW2gBwYFK4EEACKhZANiAAR3Il6V61OwAnb6oYm4hQ4TVVaGQ2QGzrSi
eYGoRewNhAaZ8wfemWX4fww7yNi6AmUzWV8Su5Qq3dtN3nLpKUEaJrTvfjtowrr/
ZtU1fZxzI/agEpG2+uLFW6JNdYzp67w=
-----END EC PRIVATE KEY-----`)

var testKeyEC521 = mustParseECKey(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBH31vhkSH+x+J8C/xf/PRj81u3MCqgiaGdW1S1jcjEuikczbbX689
9ETHGCPtHEWw/Il1RAFaKMvndmfDVd/YapmgBwYFK4EEACOhgYkDgYYABAGNpBDA
Lx6rKQXWdWQR581uw9dTuV8zjmkSpLZ3k0qLHVlOqt00AfEL4NO+E7fxh4SuAZPb
RDMu2lx4lWOM2EyFvgFIyu8xlA9lEg5GKq+A7+y5r99RLughiDd52vGnudMspHEy
x6IpwXzTZR/T8TkluL3jDWtVNFxGBf/aEErnpeLfRQ==
-----END EC PRIVATE KEY-----`)

// example from RFC 8037, appendix A.1
var testKeyEd25519Private = ed25519.PrivateKey([]byte{
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
	0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
	0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
	// public key suffix
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
})

// example from RFC 8037, appendix A.1
var testKeyEd25519Public = ed25519.PublicKey([]byte{
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
})

var testKeyRSA1024 = mustParseRSAKey(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDCzQ4MMppUkCXTi/BjPWO2gLnaVmPhyMdo7rnccfoBnH5lCTdY
x2aK2vNkVVLi4w8zITBXAXwKB7O5iQaaXImnUD2KPReRKbyGbvkGwQGpU1UsZjzZ
uPFfbDtdWr+d2CxQUdPjKu886Lad4BsJFWSJYt06K1byYCGAYyN5hosmOQIDAQAB
AoGAO5EIYqJ2nrUVXALGlxIGk5/5NNKF6FzE3UlifA4+LI/19l9DFVqj+IHLOzr8
BXT5COF1LqW9kDOauXk1E66ISJ/vAFYvS+hIugKDqUhpBTpgPa2nyJGOjUHScvIP
sVdo1unpYU40bvhhy7HD4kwQvohYq9w5KW732jpqPJK5TKECQQD3XpZGlXAJ+O/5
p97Xwt6Rz7peG1Aqx3TlzVUvOPCXT8rnycEub0j52sYZUwg3dtf763R385pJmBJs
TJc2oN9PAkEAyZjyDqGUM6IJy7O55Ylsy3dxply7NIym+BM4p8MiEwzHZb5dXgX3
pxuPlLX3DojlGWNcLB5+gw1ZSq9Y5dz/9wJBAOQoQtUBemBIUhbj5d795sl4Xn30
FUIPy9s1Qy+WBhqZxx148gxBKn8BcRvkgLyfieDasAb/Ebx1XfCzx/jj8nMCQBNr
WT3RkL4ciMcHjAuxXjqHSfpVim74cYkKCPYYFOsy2u5RFRtehcmiHQWdNaw/wZnd
eV6CnXswSP6pv219CWcCQBv3wKhme0RkuPuyG4MUFFeHxOcilasHx/nWiz8U90Tm
hP30X1iUlekEFj/2oneT6qWqtH4nVX18/WehPQoDoLg=
-----END RSA PRIVATE KEY-----`)

var testKeyRSA2048 = mustParseRSAKey(`-----BEGIN RSA PRIVATE KEY-----
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

var testKeyRSA4096 = mustParseRSAKey(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)

func TestErrUnsecured(t *testing.T) {
	// example from RFC 7519, subsection 6.1.
	const token = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."

	_, err := HMACCheck([]byte(token), []byte("guest"))
	if err != ErrUnsecured {
		t.Errorf("HMACCheck got error %v, want ErrUnsecured", err)
	}
	_, err = new(KeyRegister).Check([]byte(token))
	if err != ErrUnsecured {
		t.Errorf("KeyRegister Check got error %v, want ErrUnsecured", err)
	}

	const want = `jwt: algorithm "none" not in use`
	if got := ErrUnsecured.Error(); got != want {
		t.Errorf("Error got %q, want %q", got, want)
	}
}

func TestNewHMACAlgError(t *testing.T) {
	unknownAlg := "doesntexist"
	want := AlgError("doesntexist")

	if _, err := NewHMAC(unknownAlg, []byte("guest")); err != want {
		t.Errorf("NewHMAC got error %v, want %v", err, want)
	}
}

func TestNewHMACNoSecret(t *testing.T) {
	_, err := NewHMAC("HS256", []byte{})
	if err != errNoSecret {
		t.Errorf("got error %v, want %v", err, errNoSecret)
	}
}

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
	d := time.Date(2009, 2, 13, 23, 31, 30, 12e7, time.UTC)

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

func TestNumericTimeRounding(t *testing.T) {
	// The following epoch offset causes a rounding error (to 4742743139.000001)
	// when converted to nanoseconds as a double-precision floating-point.
	ts := time.Unix(4742743139, 0)
	if got := NewNumericTime(ts); *got != NumericTime(ts.Unix()) {
		t.Errorf("got %f, want %d", *got, ts.Unix())
	}
	if got := NewNumericTime(ts).Time(); !ts.Equal(got) {
		t.Errorf("got time %s from %s", got, ts)
	}
}

func TestClaimsValid(t *testing.T) {
	c := new(Claims)
	if !c.Valid(time.Time{}) {
		t.Error("invalidated claims without time limits for zero time")
	}
	if !c.Valid(time.Now()) {
		t.Error("invalidated claims without time limits")
	}

	now := time.Now()
	c.NotBefore = NewNumericTime(now)
	c.Expires = NewNumericTime(now.Add(time.Minute))

	if c.Valid(time.Time{}) {
		t.Error("validated claims with time limits for zero time")
	}
	if c.Valid(c.NotBefore.Time().Add(-time.Millisecond)) {
		t.Error("validated claims before time limit")
	}
	if !c.Valid(c.NotBefore.Time()) {
		t.Error("invalidated claims on time limit start")
	}
	if !c.Valid(c.NotBefore.Time().Add(time.Millisecond)) {
		t.Error("invalidated claims within time limit")
	}
	if c.Valid(c.Expires.Time()) {
		t.Error("validated claims on time limit end")
	}
	if c.Valid(c.Expires.Time().Add(time.Millisecond)) {
		t.Error("validated claims after time limit end")
	}
}

func TestClaimsNull(t *testing.T) {
	const name = "x"
	c := Claims{Set: map[string]interface{}{name: nil}}
	if _, ok := c.String(name); ok {
		t.Error("null accepted as string")
	}
	if _, ok := c.Number(name); ok {
		t.Error("null accepted as number")
	}
}

func mustParseECKey(s string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		panic("invalid PEM")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
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
