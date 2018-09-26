package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
)

var goldenECDSAs = []struct {
	key    *ecdsa.PublicKey
	token  string
	claims string
}{
	0: {
		key:    &testKeyEC256.PublicKey,
		token:  "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJjdHVudCIsImF1ZCI6ImJvYXJkIn0.AnYB6w3Zh7MBYE9uLE8Hp693DHf-1Xm_WiXl-ZTAIabuO1ER4O38T5PPkducsHPZ4NCPLqh2bprlRJGnE_s5IA",
		claims: `{"iss":"ctunt","aud":"board"}`,
	},
	1: {
		key:    &testKeyEC384.PublicKey,
		token:  "eyJhbGciOiJFUzM4NCJ9.e30.1WD7DU260TLDzwiJQa-ri7FBnXlRsOzEpTKDmMt51dzqDiYguVch7VqNLTVkHCb4oJ-LDJ8-PGaeoo4jcNkGQjGg1HUiHWEZNyUUPRbxnzTKOWD1Z3VAlPDgnhXp1i8t",
		claims: `{}`,
	},
	2: {
		key:    &testKeyEC521.PublicKey,
		token:  "eyJhbGciOiJFUzUxMiJ9.eyJzdWIiOiJha3JpZWdlciIsInByZWZpeCI6IkRyLiJ9.APhisjBsvFDWLojTWUP7uyEiilIOU4KYVEgqFr5GdJbd5ucuejztFUvzRZq8njo2s0jLqwMN6H0IhG9YHDMRKTgQAbEbOT_13tN6Xs4sTtxefuf_jlJTfTLtg9_2A22iGYgSDBTzWpunC-Ofuq4XegptS2NuC6XGTFu41DbQX6EmEb-7",
		claims: `{"sub":"akrieger","prefix":"Dr."}`,
	},
}

func TestECDSACheck(t *testing.T) {
	for i, gold := range goldenECDSAs {
		claims, err := ECDSACheck([]byte(gold.token), gold.key)
		if err != nil {
			t.Errorf("%d: check error: %s", i, err)
			continue
		}
		if !bytes.Equal([]byte(claims.Raw), []byte(gold.claims)) {
			t.Errorf("%d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}
}

var goldenHMACs = []struct {
	secret []byte
	token  string
	claims string
}{
	0: {
		// SHA-256 example from RFC 7515, appendix A.1.1
		secret: []byte{0x3, 0x23, 0x35, 0x4b, 0x2b, 0xf, 0xa5, 0xbc, 0x83, 0x7e, 0x6, 0x65, 0x77, 0x7b, 0xa6, 0x8f, 0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28, 0xa9, 0xf, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf, 0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x6, 0x47, 0xef, 0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22, 0x3d, 0x2e, 0x21, 0x72, 0x5, 0x2e, 0x4f, 0x8, 0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3},
		token:  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		claims: "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}",
	},
	1: {
		secret: []byte("secret"),
		token:  "eyJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJwcG9vdmV5Iiwic3ViIjoic21hcmNoZXIiLCJhdWQiOiJjb3JlIiwiZXhwIjoyLCJuYmYiOjEsImlhdCI6MCwianRpIjoibm90aGluZyJ9.NUVxGDBgIh3-tFl2XVpufzSH4lDEVM-dGbKxxkL1UlJNbDycQ5PpwkIxBkvzBFL0w_g6Fb3CVRhdjMpdz_pc2A",
		claims: `{"iss":"ppoovey","sub":"smarcher","aud":"core","exp":2,"nbf":1,"iat":0,"jti":"nothing"}`,
	},
}

func TestHMACCheck(t *testing.T) {
	for i, gold := range goldenHMACs {
		claims, err := HMACCheck([]byte(gold.token), gold.secret)
		if err != nil {
			t.Errorf("%d: check error: %s", i, err)
			continue
		}
		if !bytes.Equal([]byte(claims.Raw), []byte(gold.claims)) {
			t.Errorf("%d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}
}

var goldenRSAs = []struct {
	key    *rsa.PublicKey
	token  string
	claims string
}{
	0: {
		key:    &testKeyRSA2048.PublicKey,
		token:  "eyJhbGciOiJSUzI1NiJ9.eyJjb2RlIjoiMDA3In0.q7I3GX8MUwd_Rrs_NiknGp3org30cBDT4JpvQfHx8TAPZNMeQokWb3iZD-Lu0TkQbZiFWdsRrrYVJO-nI15cvkRiSRtzKD0ilaC-i3VmM6cXu2AGSRhhFR4wAaZ5ZNYicooIVf1D1DLP48UZvT-n1ysuMKRRYrnyypcG8xg4o56UEFHrLL1zvuolIsG_sZN0pnVYUEDxLfXJboPSXDYOpyHSJu36Np6s4d8IsUyr3xX-Tu6-Lktu6_5k7NIVtY8yRHThe8x0UL316E_w1Av4nlECTezUS_vSF42w3rQESPXPwaZEFTxm0ciIRn0Wm0GdLHPaKSyZscgGn64eeai57Q",
		claims: `{"code":"007"}`,
	},
}

func TestRSACheck(t *testing.T) {
	for i, gold := range goldenRSAs {
		claims, err := RSACheck([]byte(gold.token), gold.key)
		if err != nil {
			t.Errorf("%d: check error: %s", i, err)
			continue
		}
		if !bytes.Equal([]byte(claims.Raw), []byte(gold.claims)) {
			t.Errorf("%d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}
}

func TestCheckMiss(t *testing.T) {
	_, err := ECDSACheck([]byte(goldenECDSAs[0].token), &testKeyEC521.PublicKey)
	if err != ErrSigMiss {
		t.Errorf("ECDSA check got error %v, want %v", err, ErrSigMiss)
	}
	_, err = HMACCheck([]byte(goldenHMACs[0].token), nil)
	if err != ErrSigMiss {
		t.Errorf("HMAC check got error %v, want %v", err, ErrSigMiss)
	}
	_, err = RSACheck([]byte(goldenRSAs[0].token), &testKeyRSA4096.PublicKey)
	if err != ErrSigMiss {
		t.Errorf("RSA check got error %v, want %v", err, ErrSigMiss)
	}
}

// Reject the "none" algorithm with ErrUnsecured.
func Example_noneAlg() {
	_, err := HMACCheck([]byte("eyJhbGciOiJub25lIn0.e30."), nil)
	fmt.Println(err)

	//output: jwt: unsecured—no signature
}

func TestCheckAlgWrong(t *testing.T) {
	_, err := ECDSACheck([]byte(goldenRSAs[0].token), nil)
	if err != ErrAlgUnk {
		t.Errorf("RSA alg for ECDSA got error %v, want %v", err, ErrAlgUnk)
	}
	_, err = HMACCheck([]byte(goldenRSAs[0].token), nil)
	if err != ErrAlgUnk {
		t.Errorf("RSA alg for HMAC got error %v, want %v", err, ErrAlgUnk)
	}
	_, err = RSACheck([]byte(goldenHMACs[0].token), &testKeyRSA1024.PublicKey)
	if err != ErrAlgUnk {
		t.Errorf("HMAC alg for RSA got error %v, want %v", err, ErrAlgUnk)
	}
}

func TestCheckHashNotLinked(t *testing.T) {
	alg := "HB2b256"
	if _, ok := HMACAlgs[alg]; ok {
		t.Fatalf("non-standard alg %q present", alg)
	}
	HMACAlgs[alg] = crypto.BLAKE2b_256
	defer delete(HMACAlgs, alg)

	_, err := HMACCheck([]byte("eyJhbGciOiJIQjJiMjU2In0.e30.e30"), nil)
	if err != errHashLink {
		t.Errorf("got error %v, want %v", err, errHashLink)
	}
}

func TestCheckIncomplete(t *testing.T) {
	// header only
	_, err := ECDSACheck([]byte("eyJhbGciOiJFUzI1NiJ9"), &testKeyEC256.PublicKey)
	if err != errPart {
		t.Errorf("one base64 chunk got error %v, want %v", err, errPart)
	}
	_, err = RSACheck([]byte("eyJhbGciOiJub25lIn0"), &testKeyRSA1024.PublicKey)
	if err != errPart {
		t.Errorf("one base64 chunk got error %v, want %v", err, errPart)
	}

	// header + body; missing signature
	_, err = HMACCheck([]byte("eyJhbGciOiJub25lIn0.e30"), nil)
	if err != errPart {
		t.Errorf("two base64 chunks got error %v, want %v", err, errPart)
	}
}

func TestCheckBrokenBase64(t *testing.T) {
	want := "jwt: malformed header: "
	_, err := HMACCheck([]byte("*yJhbGciOiJIUzI1NiJ9.e30.4E_Bsx-pJi3kOW9wVXN8CgbATwP09D9V5gxh9-9zSZ0"), nil)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in header got error %v, want %s…", err, want)
	}

	want = "jwt: malformed payload: "
	_, err = HMACCheck([]byte("eyJhbGciOiJIUzI1NiJ9.#.hjZNKOxutvgwMhfCSZ4KXcIjuqi8lTA96fmo_6jwtZM"), nil)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in payload got error %v, want %s…", err, want)
	}

	want = "jwt: malformed signature: "
	_, err = ECDSACheck([]byte("eyJhbGciOiJFUzI1NiJ9.e30.*"), nil)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in ECDSA signature got error %v, want %s…", err, want)
	}
	_, err = HMACCheck([]byte("eyJhbGciOiJIUzI1NiJ9.e30.*"), nil)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in HMAC signature got error %v, want %s…", err, want)
	}
	_, err = RSACheck([]byte("eyJhbGciOiJSUzI1NiJ9.e30.*"), nil)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in RSA signature got error %v, want %s…", err, want)
	}
}

func TestCheckBrokenJSON(t *testing.T) {
	want := "jwt: malformed header: "
	_, err := HMACCheck([]byte("YnJva2Vu.e30."), nil)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt JSON in header got error %v, want %s…", err, want)
	}

	want = "jwt: malformed payload: "
	_, err = HMACCheck([]byte("eyJhbGciOiJIUzI1NiJ9.YnJva2Vu.5YbD-zSDmv7JQMNGAyVHIFF-2-_eBbqsV5XOZOoaO2c"), nil)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt JSON in payload got error %v, want %s…", err, want)
	}
}
