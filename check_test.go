package jwt

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/pascaldekloe/goe/verify"
)

var goldenHMACs = []struct {
	secret []byte
	serial string
	claims *Claims
}{
	0: {
		// SHA-256 example from RFC 7515, appendix A.1.1
		secret: []byte{0x3, 0x23, 0x35, 0x4b, 0x2b, 0xf, 0xa5, 0xbc, 0x83, 0x7e, 0x6, 0x65, 0x77, 0x7b, 0xa6, 0x8f, 0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28, 0xa9, 0xf, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf, 0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x6, 0x47, 0xef, 0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22, 0x3d, 0x2e, 0x21, 0x72, 0x5, 0x2e, 0x4f, 0x8, 0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3},
		serial: "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		claims: &Claims{
			Raw: json.RawMessage([]byte("{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}")),
			Set: map[string]interface{}{
				"iss": "joe",
				"exp": 1300819380.0,
				"http://example.com/is_root": true,
			},
			Registered: Registered{
				Issuer:  "joe",
				Expires: NewNumericTime(time.Unix(1300819380, 0)),
			},
		},
	},
}

func TestHMACCheck(t *testing.T) {
	for i, gold := range goldenHMACs {
		claims, err := HMACCheck(gold.serial, gold.secret)
		if err != nil {
			t.Errorf("%d: check error: %s", i, err)
			continue
		}
		verify.Values(t, "claims", claims, gold.claims)
	}
}

var goldenRSAs = []struct {
	key    string
	serial string
	claims string
}{
	0: {
		// SHA-256 test from github.com/dgrijalva/jwt-go
		key: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7
mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBp
HssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2
XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b
ODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy
7wIDAQAB
-----END PUBLIC KEY-----`,
		serial: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		claims: `{"foo":"bar"}`,
	},
}

func TestRSACheck(t *testing.T) {
	for i, gold := range goldenRSAs {
		block, _ := pem.Decode([]byte(gold.key))
		if block == nil {
			t.Fatal("invalid PEM public key")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := RSACheck(gold.serial, key.(*rsa.PublicKey))
		if err != nil {
			t.Errorf("%d: check error: %s", i, err)
			continue
		}
		if !bytes.Equal([]byte(claims.Raw), []byte(gold.claims)) {
			t.Errorf("%d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
			continue
		}
	}
}
