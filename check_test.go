package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
		token:  "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJjdHVudCIsImF1ZCI6WyJib2FyZCJdfQ.zBjKIRdBzKiTUe34edjYRQyPy5-c_UkkBn3rip3GxvHeEhJnoop3TEWCdO4luIeX6Cfj9uJUOqIskra5-CHrXA",
		claims: `{"iss":"ctunt","aud":["board"]}`,
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
		if string(claims.Raw) != gold.claims {
			t.Errorf("%d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}
}

var goldenEdDSAs = []struct {
	key    ed25519.PublicKey
	token  string
	claims string
}{
	0: {
		key:    testKeyEd25519Public,
		token:  "eyJhbGciOiJFZERTQSJ9.eyAiYXVkIjogIkppbGxldHRlIiwgImp0aSI6ICJjcmlzaXMtdmVzdCIgfQ.HWhMmi3DO74IOYujxYdbSqrNta9IjQsY3QB8JI2vHhwkGTXXwl_gCK93nbROlR4aW37a8EKpBfnqMc7HAhVkBg",
		claims: `{ "aud": "Jillette", "jti": "crisis-vest" }`,
	},
}

func TestEdDSACheck(t *testing.T) {
	for i, gold := range goldenEdDSAs {
		claims, err := EdDSACheck([]byte(gold.token), gold.key)
		if err != nil {
			t.Errorf("%d: check error: %s", i, err)
			continue
		}
		if string(claims.Raw) != gold.claims {
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
		if string(claims.Raw) != gold.claims {
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
		if string(claims.Raw) != gold.claims {
			t.Errorf("%d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}
}

func TestCheckAudiences(t *testing.T) {
	const token = "eyJhbGciOiJSUzUxMiJ9.eyJhdWQiOlsiT3RoZXIgQmFycnkiLCJEZXNlcnQgRWFnbGUiLG51bGxdfQ.TtztyCP1yhNcr6DfwuHul9pBNlIXiNNvEC-lob4feS6M6TxbBu0gdhM70vtbMX7eMRPvyd1_4upq01hbGKl50WTpFPtEyb-nGG0jBjgin2gLp8rugKSZHepipOVeKcLl7ruwk40AV-wc_8RbApyT2Bsl8p90MW6tMDobAZEEVt4"
	claims, err := ParseWithoutCheck([]byte(token))
	if err != nil {
		t.Fatal("check error:", err)
	}

	// note the null pointer
	const payload = `{"aud":["Other Barry","Desert Eagle",null]}`
	if string(claims.Raw) != payload {
		t.Errorf("got JSON %q, want %q", claims.Raw, payload)
	}

	if !claims.AcceptAudience("Other Barry") {
		t.Error("Other Barry not accepted")
	}
	if !claims.AcceptAudience("Desert Eagle") {
		t.Error("Desert Eagle not accepted")
	}
	if claims.AcceptAudience("") {
		t.Error("no audience accepted")
	}

	if got, want := len(claims.Audiences), 2; got != want {
		t.Errorf(`got %d audiences, want %d`, got, want)
	}
}

func TestCheckMiss(t *testing.T) {
	_, err := ECDSACheck([]byte(goldenECDSAs[0].token), &testKeyEC521.PublicKey)
	if err != ErrSigMiss {
		t.Errorf("ECDSA check got error %v, want %v", err, ErrSigMiss)
	}

	randEdKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = EdDSACheck([]byte(goldenEdDSAs[0].token), randEdKey)
	if err != ErrSigMiss {
		t.Errorf("ECDSA check got error %v, want %v", err, ErrSigMiss)
	}

	_, err = HMACCheck([]byte(goldenHMACs[0].token), []byte("guest"))
	if err != ErrSigMiss {
		t.Errorf("HMAC check got error %v, want %v", err, ErrSigMiss)
	}

	_, err = RSACheck([]byte(goldenRSAs[0].token), &testKeyRSA4096.PublicKey)
	if err != ErrSigMiss {
		t.Errorf("RSA check got error %v, want %v", err, ErrSigMiss)
	}
}

func TestCheckNoSecret(t *testing.T) {
	_, err := HMACCheck(nil, nil)
	if err != errNoSecret {
		t.Errorf("got error %v, want %v", err, errNoSecret)
	}
}

func TestCheckHashNotLinked(t *testing.T) {
	alg := "HB2b256"
	if _, ok := HMACAlgs[alg]; ok {
		t.Fatalf("non-standard alg %q present", alg)
	}
	HMACAlgs[alg] = crypto.BLAKE2b_256
	defer delete(HMACAlgs, alg)

	_, err := HMACCheck([]byte("eyJhbGciOiJIQjJiMjU2In0.e30.e30"), []byte("guest"))
	if err != errHashLink {
		t.Errorf("got error %v, want %v", err, errHashLink)
	}
}

func TestJOSEExtension(t *testing.T) {
	_, err := HMACCheck([]byte("eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiZXhwIl0sImV4cCI6MTM2MzI4NDAwMH0.e30.8Ep7gVUA49twmE6NYAiEwVwwtn_UmJEkOH1uQSPPYr0"), []byte("guest"))
	const want = "jwt: unsupported critical extension in JOSE header: [\"exp\"]"
	if err == nil || err.Error() != want {
		t.Errorf("got error %q, want %q", err, want)
	}
}

func TestErrPart(t *testing.T) {
	_, err := ECDSACheck([]byte("eyJhbGciOiJFUzI1NiJ9"), &testKeyEC256.PublicKey)
	if err != errPart {
		t.Errorf("header only got error %v", err)
	}
	_, err = RSACheck([]byte("eyJhbGciOiJub25lIn0"), &testKeyRSA1024.PublicKey)
	if err != errPart {
		t.Errorf("unsecured header only got error %v", err)
	}

	_, err = ECDSACheck([]byte("eyJhbGciOiJFUzI1NiJ9.e30"), &testKeyEC384.PublicKey)
	if err != errPart {
		t.Errorf("one dot got error %v", err)
	}
	_, err = HMACCheck([]byte("eyJhbGciOiJub25lIn0.e30"), []byte("guest"))
	if err != errPart {
		t.Errorf("unsecured one dot got error %v", err)
	}
}

func TestRejectNone(t *testing.T) {
	// example from RFC 7519, subsection 6.1.
	const token = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
	_, err := HMACCheck([]byte(token), []byte("guest"))
	if err == nil {
		t.Fatal("no error")
	}
	if want := `jwt: algorithm "none" not in use`; err.Error() != want {
		t.Errorf("got error %v, want %s", err, want)
	}
}

func TestCheckBrokenBase64(t *testing.T) {
	want := "jwt: malformed JOSE header: "
	_, err := HMACCheck([]byte("*yJhbGciOiJIUzI1NiJ9.e30.4E_Bsx-pJi3kOW9wVXN8CgbATwP09D9V5gxh9-9zSZ0"), []byte("guest"))
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in header got error %v, want %s…", err, want)
	}

	want = "jwt: malformed payload: "
	_, err = HMACCheck([]byte("eyJhbGciOiJIUzI1NiJ9.#.yuPeHF3zFJaCselXdCR23yxl5Don3rD3ABnzcO_460M"), []byte("guest"))
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in payload got error %v, want %s…", err, want)
	}

	want = "jwt: malformed signature: "
	_, err = ECDSACheck([]byte("eyJhbGciOiJFUzI1NiJ9.e30.*"), nil)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in ECDSA signature got error %v, want %s…", err, want)
	}
	_, err = HMACCheck([]byte("eyJhbGciOiJIUzI1NiJ9.e30.*"), []byte("guest"))
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in HMAC signature got error %v, want %s…", err, want)
	}
	_, err = RSACheck([]byte("eyJhbGciOiJSUzI1NiJ9.e30.*"), nil)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in RSA signature got error %v, want %s…", err, want)
	}
	_, err = ParseWithoutCheck([]byte("eyJhbGciOiJSUzI1NiJ9.e30.*"))
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in skipped signature got error %v, want %s…", err, want)
	}
}

func TestCheckBrokenJSON(t *testing.T) {
	want := "jwt: malformed JOSE header: "
	_, err := EdDSACheck([]byte("YnJva2Vu.e30."), testKeyEd25519Public)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt JSON in header got error %v, want %s…", err, want)
	}

	// example from RFC 8037, appendix A.4 (and A.5)
	brokenPayload := "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	want = "jwt: malformed payload: "
	_, err = EdDSACheck([]byte(brokenPayload), testKeyEd25519Public)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt JSON in payload got error %v, want %s…", err, want)
	}
}
